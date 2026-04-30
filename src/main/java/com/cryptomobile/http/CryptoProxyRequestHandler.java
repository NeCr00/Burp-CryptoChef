package com.cryptomobile.http;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import com.cryptomobile.config.Config;
import com.cryptomobile.config.ConfigStore;
import com.cryptomobile.crypto.Pipeline;

/**
 * Decrypts proxy-intercepted requests on the way IN from the client app so
 * that Burp's proxy intercept view and HTTP history show plaintext throughout.
 *
 * <p>Pairs with {@link CryptoHttpHandler#handleHttpRequestToBeSent} which
 * re-encrypts before the wire, and with {@link CryptoProxyResponseHandler}
 * which re-encrypts responses on the way back to the client.
 *
 * <p>No-ops when auto-mode is off, proxy is not in the enabled-tools list,
 * the request isn't in scope, or the body at the configured location doesn't
 * look like ciphertext (the latter lets plaintext error/health bodies pass
 * through untouched).
 */
public final class CryptoProxyRequestHandler implements ProxyRequestHandler {

    private final MontoyaApi api;
    private final ConfigStore store;
    private final ScopeMatcher scope;

    public CryptoProxyRequestHandler(MontoyaApi api, ConfigStore store) {
        this.api = api;
        this.store = store;
        this.scope = new ScopeMatcher(api);
    }

    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest request) {
        Config cfg = store.get();
        if (cfg == null || !cfg.applyToRequests || !cfg.applyToProxy) {
            return ProxyRequestReceivedAction.continueWith(request);
        }

        String url;
        try { url = request.url(); } catch (Exception e) { return ProxyRequestReceivedAction.continueWith(request); }
        String host = safeHost(request);
        ScopeMatcher.Match m = scope.pickMatch(url, host, cfg);
        if (m == null || m.pipeline() == null) {
            api.logging().logToOutput("[CryptoChef] PRH.reqReceived " + url + " → skip (no scope match)");
            return ProxyRequestReceivedAction.continueWith(request);
        }
        Config.NamedPipeline np = m.pipeline();
        Config.BodyLocation loc = m.location() != null ? m.location() : new Config.BodyLocation();

        String notes = noteOf(request.annotations());
        if (CryptoHttpHandler.hasNote(notes, CryptoHttpHandler.NOTE_PLAINTEXT)) {
            api.logging().logToOutput("[CryptoChef] PRH.reqReceived " + url + " → skip (already cm:plaintext)");
            return ProxyRequestReceivedAction.continueWith(request);
        }

        try {
            BodyLocator.Extract ex = BodyLocator.extractFromRequest(request, loc);
            if (ex == null || ex.ciphertext == null || ex.ciphertext.length == 0) {
                api.logging().logToOutput("[CryptoChef] PRH.reqReceived " + url + " → skip (no body at configured location)");
                Annotations a = request.annotations()
                        .withNotes(appendNote(notes, CryptoHttpHandler.NOTE_SKIPPED));
                return ProxyRequestReceivedAction.continueWith(request, a);
            }

            // If the client sent plaintext (e.g. unencrypted health check or error),
            // don't try to decrypt — pass through untouched.
            if (CryptoHeuristics.looksLikePlaintext(ex.ciphertext)) {
                api.logging().logToOutput("[CryptoChef] PRH.reqReceived " + url + " → skip (body already looks plaintext)");
                Annotations a = request.annotations()
                        .withNotes(appendNote(notes, CryptoHttpHandler.NOTE_SKIPPED));
                return ProxyRequestReceivedAction.continueWith(request, a);
            }

            Pipeline pipe = Pipeline.fromConfig(np, cfg);
            byte[] plain = pipe.decrypt(ex.ciphertext);
            HttpRequest modified = BodyLocator.reinsertIntoRequest(request, loc, plain, ex);
            api.logging().logToOutput("[CryptoChef] PRH.reqReceived " + url
                    + " → decrypted (" + ex.ciphertext.length + "B → " + plain.length + "B) via pipeline '" + np.name + "'");

            Annotations a = request.annotations()
                    .withHighlightColor(HighlightColor.CYAN)
                    .withNotes(appendNote(notes, CryptoHttpHandler.NOTE_PLAINTEXT));
            return ProxyRequestReceivedAction.continueWith(modified, a);
        } catch (Exception e) {
            api.logging().logToError("[CryptoChef] proxy-decrypt-on-receive failed for " + url + ": " + CryptoHttpHandler.truncate(e));
            Annotations a = request.annotations()
                    .withHighlightColor(HighlightColor.RED)
                    .withNotes(appendNote(notes, CryptoHttpHandler.NOTE_ERROR_PREFIX + CryptoHttpHandler.errorTag(e)));
            return ProxyRequestReceivedAction.continueWith(request, a);
        }
    }

    @Override
    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest request) {
        // Re-encrypt proxy-bound requests HERE, not in the HttpHandler hook.
        //
        // Why here instead of HttpHandler.handleHttpRequestToBeSent?
        //   Burp's Proxy History snapshots the request at the point it leaves
        //   the proxy pipeline. If we re-encrypt downstream in HttpHandler,
        //   Proxy History's Pretty/Raw tabs show the re-encrypted (ciphertext)
        //   body — which defeats the entire purpose of Auto mode. By doing
        //   the re-encryption here, history still captures the plaintext
        //   version we set in handleRequestReceived, and the wire gets the
        //   correctly formatted ciphertext.
        Config cfg = store.get();
        if (cfg == null || !cfg.applyToRequests || !cfg.applyToProxy) {
            return ProxyRequestToBeSentAction.continueWith(request);
        }

        String url;
        try { url = request.url(); } catch (Exception e) { return ProxyRequestToBeSentAction.continueWith(request); }
        String host = safeHost(request);
        ScopeMatcher.Match m = scope.pickMatch(url, host, cfg);
        if (m == null || m.pipeline() == null) return ProxyRequestToBeSentAction.continueWith(request);
        Config.NamedPipeline np = m.pipeline();
        Config.BodyLocation loc = m.location() != null ? m.location() : new Config.BodyLocation();

        String notes = noteOf(request.annotations());

        // Only re-encrypt if handleRequestReceived marked us as holding plaintext.
        // If the original client request was already plaintext at this location
        // (no decrypt happened), leave it alone.
        boolean markedPlain = CryptoHttpHandler.hasNote(notes, CryptoHttpHandler.NOTE_PLAINTEXT);
        if (!markedPlain) {
            api.logging().logToOutput("[CryptoChef] PRH.reqToBeSent " + url + " → skip (not marked cm:plaintext)");
            return ProxyRequestToBeSentAction.continueWith(request);
        }

        try {
            BodyLocator.Extract ex = BodyLocator.extractFromRequest(request, loc);
            if (ex == null || ex.ciphertext == null || ex.ciphertext.length == 0) {
                api.logging().logToOutput("[CryptoChef] PRH.reqToBeSent " + url + " → skip (no body at configured location)");
                return ProxyRequestToBeSentAction.continueWith(request);
            }

            // Belt-and-braces: if the body already looks opaque, skip so we
            // don't double-encrypt if the user pasted ciphertext manually.
            if (CryptoHeuristics.looksLikeCiphertext(ex.ciphertext)) {
                api.logging().logToOutput("[CryptoChef] PRH.reqToBeSent " + url + " → skip (body already looks ciphertext)");
                return ProxyRequestToBeSentAction.continueWith(request);
            }

            Pipeline pipe = Pipeline.fromConfig(np, cfg);
            byte[] cipher = pipe.encrypt(ex.ciphertext);
            HttpRequest modified = BodyLocator.reinsertIntoRequest(request, loc, cipher, ex);
            api.logging().logToOutput("[CryptoChef] PRH.reqToBeSent " + url
                    + " → re-encrypted (" + ex.ciphertext.length + "B → " + cipher.length + "B) via pipeline '" + np.name + "'");

            Annotations a = request.annotations()
                    .withHighlightColor(HighlightColor.GREEN)
                    .withNotes(appendNote(notes, CryptoHttpHandler.NOTE_CIPHERTEXT));
            return ProxyRequestToBeSentAction.continueWith(modified, a);
        } catch (Exception e) {
            api.logging().logToError("[CryptoChef] proxy-encrypt-on-send failed for " + url + ": " + CryptoHttpHandler.truncate(e));
            Annotations a = request.annotations()
                    .withHighlightColor(HighlightColor.RED)
                    .withNotes(appendNote(notes, CryptoHttpHandler.NOTE_ERROR_PREFIX + CryptoHttpHandler.errorTag(e)));
            return ProxyRequestToBeSentAction.continueWith(request, a);
        }
    }

    private static String safeHost(HttpRequest req) {
        try { return req.httpService().host(); } catch (Exception e) { return ""; }
    }

    private static String noteOf(Annotations a) {
        String s = a == null ? null : a.notes();
        return s == null ? "" : s;
    }

    private static String appendNote(String existing, String add) {
        return CryptoHttpHandler.appendNote(existing, add);
    }
}
