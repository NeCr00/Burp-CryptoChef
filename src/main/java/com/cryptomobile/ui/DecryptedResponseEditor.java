package com.cryptomobile.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.RawEditor;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.EditorMode;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import com.cryptomobile.config.Config;
import com.cryptomobile.config.ConfigStore;
import com.cryptomobile.crypto.Pipeline;
import com.cryptomobile.http.BodyLocator;
import com.cryptomobile.http.CryptoHeuristics;
import com.cryptomobile.http.ScopeMatcher;
import com.cryptomobile.http.ScopeMatcher.Match;

import java.awt.Component;

/** "Decrypted" tab for HTTP responses. Symmetric to {@link DecryptedRequestEditor}. */
public final class DecryptedResponseEditor implements ExtensionProvidedHttpResponseEditor {

    private final MontoyaApi api;
    private final ConfigStore store;
    private final ScopeMatcher scope;
    private final RawEditor editor;

    private HttpRequestResponse currentPair;
    private HttpResponse current;
    private BodyLocator.Extract lastExtract;
    private Config.BodyLocation lastLocation;
    private boolean lastWasPlaintext;
    /** Cache of last successful decrypt — see {@link DecryptedRequestEditor}. */
    private byte[] cachedCiphertextRef;
    private byte[] cachedPlaintext;

    public DecryptedResponseEditor(MontoyaApi api, ConfigStore store, EditorCreationContext ctx) {
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

    @Override public HttpResponse getResponse() {
        if (!isModified() || current == null) return current;
        return reencrypt();
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse reqRes) {
        if (reqRes == null || reqRes.response() == null || reqRes.request() == null) return false;
        Config cfg = store.get();
        if (cfg == null || cfg.scopeRules == null || cfg.scopeRules.isEmpty()) return false;
        String url;
        try { url = reqRes.request().url(); } catch (Exception e) { return false; }
        String host = reqRes.request().httpService() == null ? "" : reqRes.request().httpService().host();
        return scope.anyMatch(url, host, cfg);
    }

    @Override
    public void setRequestResponse(HttpRequestResponse reqRes) {
        this.currentPair = reqRes;
        this.current = reqRes == null ? null : reqRes.response();
        render();
    }

    private void render() {
        lastWasPlaintext = false;
        if (current == null || currentPair == null) {
            editor.setContents(ByteArray.byteArray(new byte[0]));
            return;
        }
        Config cfg = store.get();
        String url;
        try { url = currentPair.request().url(); } catch (Exception e) { showOriginalFull(); return; }
        String host = currentPair.request().httpService() == null ? "" : currentPair.request().httpService().host();
        Match m = scope.pickMatch(url, host, cfg);
        if (m == null || m.pipeline() == null) { showOriginalFull(); return; }
        lastLocation = m.location() != null ? m.location() : new Config.BodyLocation();

        try {
            Pipeline p = Pipeline.fromConfig(m.pipeline(), cfg);
            lastExtract = BodyLocator.extractFromResponse(current, lastLocation);
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

            HttpResponse full = BodyLocator.reinsertIntoResponse(current, lastLocation, displayContent, lastExtract);
            editor.setContents(full.toByteArray());
        } catch (Exception e) {
            api.logging().logToError("[CryptoChef] decrypted-tab render failed: "
                    + (e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage()));
            showOriginalFull();
        }
    }

    private void showOriginalFull() {
        if (current == null) {
            editor.setContents(ByteArray.byteArray(new byte[0]));
            return;
        }
        editor.setContents(current.toByteArray());
    }

    private HttpResponse reencrypt() {
        try {
            Config cfg = store.get();
            byte[] editedRaw = editor.getContents().getBytes();
            HttpResponse edited = HttpResponse.httpResponse(ByteArray.byteArray(editedRaw));

            String url  = currentPair.request().url();
            String host = currentPair.request().httpService() == null ? "" : currentPair.request().httpService().host();
            Match m = scope.pickMatch(url, host, cfg);
            if (m == null || m.pipeline() == null) return edited;
            Config.BodyLocation loc = lastLocation != null ? lastLocation
                    : (m.location() != null ? m.location() : new Config.BodyLocation());

            BodyLocator.Extract ex = BodyLocator.extractFromResponse(edited, loc);
            if (ex == null) return edited;

            if (lastWasPlaintext) {
                return edited;
            }
            Pipeline p = Pipeline.fromConfig(m.pipeline(), cfg);
            byte[] cipher = p.encrypt(ex.ciphertext);
            return BodyLocator.reinsertIntoResponse(edited, loc, cipher, ex);
        } catch (Exception e) {
            api.logging().logToError("[CryptoChef] response re-encrypt failed: " + e);
            return current;
        }
    }
}
