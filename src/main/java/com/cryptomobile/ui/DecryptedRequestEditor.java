package com.cryptomobile.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.RawEditor;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.EditorMode;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import com.cryptomobile.config.Config;
import com.cryptomobile.config.ConfigStore;
import com.cryptomobile.crypto.Pipeline;
import com.cryptomobile.http.BodyLocator;
import com.cryptomobile.http.CryptoHeuristics;
import com.cryptomobile.http.ScopeMatcher;
import com.cryptomobile.http.ScopeMatcher.Match;

import java.awt.Component;

/**
 * "Decrypted" tab for HTTP requests.
 *
 * <p>Shows the full HTTP request (method line, headers, body) with the
 * ciphertext at the configured body-location replaced by its decrypted,
 * pretty-printed form. The user can edit any part of the request — on
 * commit we parse the edited bytes back into an {@code HttpRequest},
 * re-extract the (now-plaintext) content at the body-location,
 * re-encrypt it, and splice it back so the message that leaves Burp
 * is still valid on the wire.
 *
 * <p>Uses {@link RawEditor} rather than the full {@code HttpRequestEditor}
 * because the latter hosts every registered extension-provided tab,
 * including this one — embedding it would cause recursive sub-tab
 * stacking on every activation.
 */
public final class DecryptedRequestEditor implements ExtensionProvidedHttpRequestEditor {

    private final MontoyaApi api;
    private final ConfigStore store;
    private final ScopeMatcher scope;
    private final RawEditor editor;

    private HttpRequest current;
    private BodyLocator.Extract lastExtract;
    private Config.BodyLocation lastLocation;
    /** True if the configured ciphertext location actually held plaintext at
     *  render time; on commit we must splice raw (don't re-encrypt). */
    private boolean lastWasPlaintext;
    /** Cache of the last successful decrypt so quick re-renders (e.g. user
     *  scrubbing through Proxy History) don't re-run an expensive pipeline.
     *  Keyed by ciphertext array <i>identity</i> — Burp creates a fresh byte[]
     *  per HttpRequest so identity equality is the right semantic and avoids
     *  pinning bytes longer than necessary. */
    private byte[] cachedCiphertextRef;
    private byte[] cachedPlaintext;

    public DecryptedRequestEditor(MontoyaApi api, ConfigStore store, EditorCreationContext ctx) {
        this.api = api;
        this.store = store;
        this.scope = new ScopeMatcher(api);
        EditorMode mode = ctx.editorMode();
        this.editor = (mode == EditorMode.READ_ONLY)
                ? api.userInterface().createRawEditor(EditorOptions.READ_ONLY)
                : api.userInterface().createRawEditor();
    }

    @Override public String caption()          { return "Decrypted"; }
    @Override public Component uiComponent()   { return editor.uiComponent(); }
    @Override public Selection selectedData()  { return editor.selection().orElse(null); }
    @Override public boolean isModified()      { return editor.isModified(); }

    @Override public HttpRequest getRequest() {
        if (!isModified() || current == null) return current;
        return reencrypt();
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse reqRes) {
        if (reqRes == null || reqRes.request() == null) return false;
        Config cfg = store.get();
        if (cfg == null || cfg.scopeRules == null || cfg.scopeRules.isEmpty()) return false;
        HttpRequest req = reqRes.request();
        String url;
        try { url = req.url(); } catch (Exception e) { return false; }
        String host = req.httpService() == null ? "" : req.httpService().host();
        return scope.anyMatch(url, host, cfg);
    }

    @Override
    public void setRequestResponse(HttpRequestResponse reqRes) {
        this.current = reqRes == null ? null : reqRes.request();
        render();
    }

    private void render() {
        lastWasPlaintext = false;
        if (current == null) {
            editor.setContents(ByteArray.byteArray(new byte[0]));
            return;
        }
        Config cfg = store.get();

        String url;
        try { url = current.url(); } catch (Exception e) { showOriginalFull(); return; }
        String host = current.httpService() == null ? "" : current.httpService().host();
        Match m = scope.pickMatch(url, host, cfg);
        if (m == null || m.pipeline() == null) { showOriginalFull(); return; }
        lastLocation = m.location() != null ? m.location() : new Config.BodyLocation();

        try {
            Pipeline p = Pipeline.fromConfig(m.pipeline(), cfg);
            lastExtract = BodyLocator.extractFromRequest(current, lastLocation);
            if (lastExtract == null) { showOriginalFull(); return; }

            byte[] displayContent;
            if (CryptoHeuristics.looksLikePlaintext(lastExtract.ciphertext)) {
                lastWasPlaintext = true;
                displayContent = PrettyPrint.maybePretty(lastExtract.ciphertext);
            } else if (cachedCiphertextRef == lastExtract.ciphertext && cachedPlaintext != null) {
                displayContent = PrettyPrint.maybePretty(cachedPlaintext);
            } else {
                byte[] plain = p.decrypt(lastExtract.ciphertext);
                cachedCiphertextRef = lastExtract.ciphertext;
                cachedPlaintext = plain;
                displayContent = PrettyPrint.maybePretty(plain);
            }

            // Splice plaintext into the original request at the body-location
            // and display the full HTTP message (method line + headers + body).
            HttpRequest full = BodyLocator.reinsertIntoRequest(current, lastLocation, displayContent, lastExtract);
            editor.setContents(full.toByteArray());
        } catch (Exception e) {
            api.logging().logToError("[CryptoChef] decrypted-tab render failed: "
                    + (e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage()));
            showOriginalFull();
        }
    }

    /** Fallback when we can't decrypt — show the full raw HTTP message so the
     *  tab is never empty. */
    private void showOriginalFull() {
        if (current == null) {
            editor.setContents(ByteArray.byteArray(new byte[0]));
            return;
        }
        editor.setContents(current.toByteArray());
    }

    /**
     * Parse the user's edited bytes back into an {@link HttpRequest}, then
     * re-encrypt the (edited) content at the body-location so the wire still
     * carries valid ciphertext. Returning the parsed edited request preserves
     * any header/method/path edits the user made.
     */
    private HttpRequest reencrypt() {
        try {
            Config cfg = store.get();
            byte[] editedRaw = editor.getContents().getBytes();
            HttpRequest edited = (current.httpService() != null)
                    ? HttpRequest.httpRequest(current.httpService(), ByteArray.byteArray(editedRaw))
                    : HttpRequest.httpRequest(ByteArray.byteArray(editedRaw));

            String url;
            try { url = edited.url(); } catch (Exception e) { url = ""; }
            String host = edited.httpService() == null ? "" : edited.httpService().host();
            Match m = scope.pickMatch(url, host, cfg);
            if (m == null || m.pipeline() == null) return edited;
            Config.BodyLocation loc = lastLocation != null ? lastLocation
                    : (m.location() != null ? m.location() : new Config.BodyLocation());

            BodyLocator.Extract ex = BodyLocator.extractFromRequest(edited, loc);
            if (ex == null) return edited;

            if (lastWasPlaintext) {
                // Body was plaintext all along — splice user's edits back without encrypting.
                return edited;
            }
            Pipeline p = Pipeline.fromConfig(m.pipeline(), cfg);
            byte[] cipher = p.encrypt(ex.ciphertext);
            return BodyLocator.reinsertIntoRequest(edited, loc, cipher, ex);
        } catch (Exception e) {
            api.logging().logToError("[CryptoChef] re-encrypt on commit failed: " + e);
            return current;
        }
    }
}
