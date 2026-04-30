package com.cryptomobile.http;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;
import com.cryptomobile.config.Config;
import com.cryptomobile.config.ConfigStore;
import com.cryptomobile.crypto.Pipeline;

/**
 * Re-encrypts proxy responses on the way BACK to the client app so the app
 * receives valid ciphertext even though Burp stored/displayed plaintext.
 *
 * <p>By the time this handler runs, {@link CryptoHttpHandler#handleHttpResponseReceived}
 * has already decrypted the wire bytes and annotated the response with
 * {@link CryptoHttpHandler#NOTE_PLAINTEXT}. This handler detects that marker
 * (or falls back to the content heuristic) and encrypts before the client sees it.
 */
public final class CryptoProxyResponseHandler implements ProxyResponseHandler {

    private final MontoyaApi api;
    private final ConfigStore store;
    private final ScopeMatcher scope;

    public CryptoProxyResponseHandler(MontoyaApi api, ConfigStore store) {
        this.api = api;
        this.store = store;
        this.scope = new ScopeMatcher(api);
    }

    @Override
    public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse response) {
        // HttpHandler.handleHttpResponseReceived already decrypted — no-op.
        return ProxyResponseReceivedAction.continueWith(response);
    }

    @Override
    public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse response) {
        Config cfg = store.get();
        if (cfg == null || !cfg.applyToResponses || !cfg.applyToProxy) {
            return ProxyResponseToBeSentAction.continueWith(response);
        }

        HttpRequest init = response.initiatingRequest();
        if (init == null) return ProxyResponseToBeSentAction.continueWith(response);

        String url;
        try { url = init.url(); } catch (Exception e) { return ProxyResponseToBeSentAction.continueWith(response); }
        String host = safeHost(init);
        ScopeMatcher.Match m = scope.pickMatch(url, host, cfg);
        if (m == null || m.pipeline() == null) return ProxyResponseToBeSentAction.continueWith(response);
        Config.NamedPipeline np = m.pipeline();
        Config.BodyLocation loc = m.location() != null ? m.location() : new Config.BodyLocation();

        String notes = noteOf(response.annotations());
        // Only encrypt if HttpHandler marked us as holding plaintext. If the
        // response went untouched earlier (e.g. server returned a plaintext
        // error that we deliberately skipped), don't re-encrypt either.
        boolean markedPlain = CryptoHttpHandler.hasNote(notes, CryptoHttpHandler.NOTE_PLAINTEXT);
        if (!markedPlain) {
            api.logging().logToOutput("[CryptoChef] PRH.resToBeSent " + url + " → skip (not marked cm:plaintext)");
            return ProxyResponseToBeSentAction.continueWith(response);
        }

        try {
            BodyLocator.Extract ex = BodyLocator.extractFromResponse(response, loc);
            if (ex == null || ex.ciphertext == null) {
                api.logging().logToOutput("[CryptoChef] PRH.resToBeSent " + url + " → skip (no body at configured location)");
                return ProxyResponseToBeSentAction.continueWith(response);
            }

            // Belt-and-braces: if the content at the location already looks
            // opaque, skip (protects against double-encrypt if the user pasted
            // ciphertext into the intercepted plaintext response).
            if (CryptoHeuristics.looksLikeCiphertext(ex.ciphertext)) {
                api.logging().logToOutput("[CryptoChef] PRH.resToBeSent " + url + " → skip (body already looks ciphertext)");
                return ProxyResponseToBeSentAction.continueWith(response);
            }

            Pipeline pipe = Pipeline.fromConfig(np, cfg);
            byte[] cipher = pipe.encrypt(ex.ciphertext);
            HttpResponse modified = BodyLocator.reinsertIntoResponse(response, loc, cipher, ex);
            api.logging().logToOutput("[CryptoChef] PRH.resToBeSent " + url
                    + " → re-encrypted (" + ex.ciphertext.length + "B → " + cipher.length + "B) via pipeline '" + np.name + "'");

            Annotations a = response.annotations()
                    .withHighlightColor(HighlightColor.GREEN)
                    .withNotes(appendNote(notes, CryptoHttpHandler.NOTE_CIPHERTEXT));
            return ProxyResponseToBeSentAction.continueWith(modified, a);
        } catch (Exception e) {
            api.logging().logToError("[CryptoChef] proxy-encrypt-on-return failed for " + url + ": " + CryptoHttpHandler.truncate(e));
            Annotations a = response.annotations()
                    .withHighlightColor(HighlightColor.RED)
                    .withNotes(appendNote(notes, CryptoHttpHandler.NOTE_ERROR_PREFIX + CryptoHttpHandler.errorTag(e)));
            return ProxyResponseToBeSentAction.continueWith(response, a);
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
