package com.cryptomobile.http;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.cryptomobile.config.Config;
import com.cryptomobile.config.ConfigStore;
import com.cryptomobile.crypto.Pipeline;

/**
 * The flagship Auto-mode handler (F4).
 *
 * <p>Design invariants:
 * <ul>
 *   <li>Burp tools see plaintext; the wire carries ciphertext.</li>
 *   <li>Failures never block traffic — original bytes are passed through,
 *       with a red highlight + annotation note.</li>
 *   <li>Idempotent: if a message is already marked as the "other" form
 *       (e.g. already ciphertext on the way out), we skip re-transforming.</li>
 * </ul>
 *
 * <p>We mark processed messages via annotation notes so we (and downstream
 * tabs) can tell at a glance whether a given message has been touched.
 */
public final class CryptoHttpHandler implements HttpHandler {

    /** Notes added to {@link Annotations} so tools/tabs can tell what state a message is in. */
    public static final String NOTE_PLAINTEXT  = "cm:plaintext";
    public static final String NOTE_CIPHERTEXT = "cm:ciphertext";
    public static final String NOTE_SKIPPED    = "cm:skipped";
    /** Error tag prefix. The full note is {@code cm:error:<ExceptionClassName>}
     *  — bounded by the small finite set of exception types we throw / catch.
     *  We deliberately do <b>not</b> embed {@code e.getMessage()} in the note
     *  because exception messages contain unique per-invocation context (byte
     *  counts, byte values, addresses) that would defeat {@link #appendNote}'s
     *  whole-token dedup and let notes grow unboundedly. Burp persists
     *  annotations into the project file alongside every HTTP message, so
     *  unbounded notes translate directly into unbounded project-file growth.
     *  The full exception detail still goes to {@code logging().logToError}. */
    public static final String NOTE_ERROR_PREFIX = "cm:error:";

    /** Hard cap on the per-message {@code notes} string. Defence-in-depth
     *  against any future code path that might bypass the dedup. */
    static final int MAX_NOTES_LEN = 256;

    /** Cap on the rendered exception text we send to {@code logToError}. */
    static final int MAX_LOGGED_ERROR_LEN = 300;

    private final MontoyaApi api;
    private final ConfigStore store;
    private final ScopeMatcher scope;

    public CryptoHttpHandler(MontoyaApi api, ConfigStore store) {
        this.api = api;
        this.store = store;
        this.scope = new ScopeMatcher(api);
    }

    // ==================== OUTBOUND (encrypt) ====================
    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        Config cfg = store.get();
        if (!cfg.applyToRequests) return pass(request);
        ToolType tt = request.toolSource().toolType();
        if (!toolEnabled(cfg, tt)) return pass(request);

        // PROXY requests are handled entirely by CryptoProxyRequestHandler:
        //   handleRequestReceived decrypts (Proxy History sees plaintext),
        //   handleRequestToBeSent re-encrypts (wire sees ciphertext).
        // If we ALSO re-encrypted here, Burp's internal history snapshot
        // would capture the ciphertext wire version and Pretty/Raw tabs
        // would show ciphertext — exactly what Auto mode is supposed to
        // avoid. So hands off proxy traffic at this hook.
        if (tt == ToolType.PROXY) return pass(request);

        String url;
        try { url = request.url(); } catch (Exception e) { return pass(request); }
        String host = safeHost(request);
        ScopeMatcher.Match m = scope.pickMatch(url, host, cfg);
        if (m == null || m.pipeline() == null) {
            api.logging().logToOutput("[CryptoChef] HH.reqToBeSent " + tt + " " + url + " → skip (no scope match)");
            return pass(request);
        }
        Config.NamedPipeline np = m.pipeline();
        Config.BodyLocation loc = m.location() != null ? m.location() : new Config.BodyLocation();

        // Idempotence: if we already encrypted this body, don't double-encrypt.
        String notes = noteOf(request.annotations());
        if (hasNote(notes, NOTE_CIPHERTEXT)) {
            api.logging().logToOutput("[CryptoChef] HH.reqToBeSent " + tt + " " + url + " → skip (already cm:ciphertext)");
            return pass(request);
        }

        // For PROXY traffic, the ProxyRequestHandler already re-encrypted and
        // annotated cm:ciphertext at handleRequestToBeSent. If we got here via
        // PROXY without that annotation, the proxy path must have failed — so
        // we re-encrypt here as a safety net. For all other tools (Repeater,
        // Intruder, Scanner) this is the only encryption point.
        try {
            Pipeline pipe = Pipeline.fromConfig(np, cfg);
            BodyLocator.Extract ex = BodyLocator.extractFromRequest(request, loc);
            if (ex == null || ex.ciphertext == null) {
                api.logging().logToOutput("[CryptoChef] HH.reqToBeSent " + tt + " " + url + " → skip (no body at configured location)");
                Annotations a = request.annotations()
                        .withNotes(appendNote(notes, NOTE_SKIPPED));
                return RequestToBeSentAction.continueWith(request, a);
            }
            if (ex.ciphertext.length == 0) {
                Annotations a = request.annotations()
                        .withNotes(appendNote(notes, NOTE_SKIPPED));
                return RequestToBeSentAction.continueWith(request, a);
            }

            // If the body at the ciphertext location already looks opaque,
            // assume the caller sent ciphertext themselves and don't re-encrypt.
            if (CryptoHeuristics.looksLikeCiphertext(ex.ciphertext)) {
                api.logging().logToOutput("[CryptoChef] HH.reqToBeSent " + tt + " " + url + " → skip (body already looks ciphertext)");
                Annotations a = request.annotations()
                        .withNotes(appendNote(notes, NOTE_SKIPPED));
                return RequestToBeSentAction.continueWith(request, a);
            }

            byte[] cipher = pipe.encrypt(ex.ciphertext);
            HttpRequest modified = BodyLocator.reinsertIntoRequest(request, loc, cipher, ex);
            api.logging().logToOutput("[CryptoChef] HH.reqToBeSent " + tt + " " + url
                    + " → encrypted (" + ex.ciphertext.length + "B → " + cipher.length + "B) via pipeline '" + np.name + "'");

            Annotations a = request.annotations()
                    .withHighlightColor(HighlightColor.GREEN)
                    .withNotes(appendNote(notes, NOTE_CIPHERTEXT));

            return RequestToBeSentAction.continueWith(modified, a);
        } catch (Exception e) {
            api.logging().logToError("[CryptoChef] encrypt-on-send failed for " + url + ": " + truncate(e));
            Annotations a = request.annotations()
                    .withHighlightColor(HighlightColor.RED)
                    .withNotes(appendNote(notes, NOTE_ERROR_PREFIX + errorTag(e)));
            return RequestToBeSentAction.continueWith(request, a);
        }
    }

    // ==================== INBOUND (decrypt) ====================
    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
        Config cfg = store.get();
        if (!cfg.applyToResponses) return pass(response);
        ToolType tt = response.toolSource().toolType();
        if (!toolEnabled(cfg, tt)) return pass(response);

        String url;
        try { url = response.initiatingRequest().url(); } catch (Exception e) { return pass(response); }
        String host = safeHost(response.initiatingRequest());
        ScopeMatcher.Match m = scope.pickMatch(url, host, cfg);
        if (m == null || m.pipeline() == null) {
            api.logging().logToOutput("[CryptoChef] HH.resReceived " + tt + " " + url + " → skip (no scope match)");
            return pass(response);
        }
        Config.NamedPipeline np = m.pipeline();
        Config.BodyLocation loc = m.location() != null ? m.location() : new Config.BodyLocation();

        String notes = noteOf(response.annotations());
        if (hasNote(notes, NOTE_PLAINTEXT)) {
            api.logging().logToOutput("[CryptoChef] HH.resReceived " + tt + " " + url + " → skip (already cm:plaintext)");
            return pass(response);
        }

        try {
            Pipeline pipe = Pipeline.fromConfig(np, cfg);
            BodyLocator.Extract ex = BodyLocator.extractFromResponse(response, loc);
            if (ex == null || ex.ciphertext == null || ex.ciphertext.length == 0) {
                api.logging().logToOutput("[CryptoChef] HH.resReceived " + tt + " " + url + " → skip (no body at configured location)");
                Annotations a = response.annotations()
                        .withNotes(appendNote(notes, NOTE_SKIPPED));
                return ResponseReceivedAction.continueWith(response, a);
            }

            // Content sniff: if the bytes at the ciphertext location already
            // look like a recognisable plaintext envelope (JSON/XML/URL-form/
            // readable text), don't try to decrypt — the server returned
            // plaintext this time (e.g. an error response).
            if (CryptoHeuristics.looksLikePlaintext(ex.ciphertext)) {
                api.logging().logToOutput("[CryptoChef] HH.resReceived " + tt + " " + url + " → skip (body already looks plaintext)");
                Annotations a = response.annotations()
                        .withNotes(appendNote(notes, NOTE_SKIPPED));
                return ResponseReceivedAction.continueWith(response, a);
            }

            byte[] plain = pipe.decrypt(ex.ciphertext);
            HttpResponse modified = BodyLocator.reinsertIntoResponse(response, loc, plain, ex);
            api.logging().logToOutput("[CryptoChef] HH.resReceived " + tt + " " + url
                    + " → decrypted (" + ex.ciphertext.length + "B → " + plain.length + "B) via pipeline '" + np.name + "'");

            Annotations a = response.annotations()
                    .withHighlightColor(HighlightColor.CYAN)
                    .withNotes(appendNote(notes, NOTE_PLAINTEXT));

            return ResponseReceivedAction.continueWith(modified, a);
        } catch (Exception e) {
            api.logging().logToError("[CryptoChef] decrypt-on-receive failed for " + url + ": " + truncate(e));
            Annotations a = response.annotations()
                    .withHighlightColor(HighlightColor.RED)
                    .withNotes(appendNote(notes, NOTE_ERROR_PREFIX + errorTag(e)));
            return ResponseReceivedAction.continueWith(response, a);
        }
    }

    // ==================== helpers ====================
    private static RequestToBeSentAction pass(HttpRequestToBeSent req)  { return RequestToBeSentAction.continueWith(req); }
    private static ResponseReceivedAction pass(HttpResponseReceived rs) { return ResponseReceivedAction.continueWith(rs); }

    private static String safeHost(HttpRequest req) {
        try { return req.httpService().host(); } catch (Exception e) { return ""; }
    }

    private static String noteOf(Annotations a) {
        String s = a == null ? null : a.notes();
        return s == null ? "" : s;
    }

    static String appendNote(String existing, String add) {
        if (add == null || add.isEmpty()) return existing == null ? "" : existing;
        if (existing == null || existing.isBlank()) {
            return add.length() > MAX_NOTES_LEN ? add.substring(0, MAX_NOTES_LEN) : add;
        }
        if (hasNote(existing, add)) return existing;
        // Defence-in-depth: never grow notes past the cap. Once we hit the
        // ceiling, stop accumulating — the existing note tokens are enough to
        // tell the user something is wrong without bloating the project file.
        if (existing.length() + 1 + add.length() > MAX_NOTES_LEN) return existing;
        return existing + " " + add;
    }

    /** Bounded, dedup-friendly tag for an exception. We use the simple class
     *  name (e.g. {@code BadPaddingException}, {@code CipherStepException}) —
     *  a small finite set across the codebase, never carries per-invocation
     *  state, and {@link #appendNote} therefore deduplicates correctly. */
    static String errorTag(Throwable t) {
        if (t == null) return "unknown";
        String n = t.getClass().getSimpleName();
        if (n == null || n.isEmpty()) return "unknown";
        // Strip suffixes that don't add diagnostic value once you know the kind.
        if (n.endsWith("Exception")) n = n.substring(0, n.length() - "Exception".length());
        if (n.isEmpty()) return "unknown";
        // Keep the tag itself short — caller writes "cm:error:" + tag.
        return n.length() > 40 ? n.substring(0, 40) : n;
    }

    /** Render an exception for the Extensions → Output log with a hard size
     *  cap. The Output buffer is in-memory but unbounded; without this cap a
     *  pathological exception (e.g. one that includes a stack-traced byte
     *  array in its message) could pin large chunks of heap. */
    static String truncate(Throwable t) {
        if (t == null) return "null";
        String s = t.getClass().getSimpleName();
        String msg = t.getMessage();
        if (msg != null && !msg.isEmpty()) s = s + ": " + msg;
        if (s.length() > MAX_LOGGED_ERROR_LEN) s = s.substring(0, MAX_LOGGED_ERROR_LEN) + "…";
        return s;
    }

    /** Whole-token membership test so {@code cm:ciphertext} does not match a
     *  longer note like {@code cm:ciphertext:extra}. Notes are separated by
     *  whitespace (see {@link #appendNote}). */
    static boolean hasNote(String notes, String needle) {
        if (notes == null || needle == null || needle.isEmpty()) return false;
        for (String tok : notes.split("\\s+")) {
            if (tok.equals(needle)) return true;
        }
        return false;
    }

    private static boolean toolEnabled(Config cfg, ToolType t) {
        if (t == null) return true;
        return switch (t) {
            case PROXY    -> cfg.applyToProxy;
            case REPEATER -> cfg.applyToRepeater;
            case INTRUDER -> cfg.applyToIntruder;
            case LOGGER   -> cfg.applyToLogger;
            case SCANNER  -> cfg.applyToScanner;
            default       -> true;
        };
    }
}
