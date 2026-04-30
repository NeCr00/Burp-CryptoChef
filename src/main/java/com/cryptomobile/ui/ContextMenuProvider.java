package com.cryptomobile.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import com.cryptomobile.config.Config;
import com.cryptomobile.config.ConfigStore;
import com.cryptomobile.crypto.Pipeline;
import com.cryptomobile.http.BodyLocator;
import com.cryptomobile.http.CryptoHeuristics;
import com.cryptomobile.http.ScopeMatcher;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Repeater / Proxy / Logger right-click menu under
 * Extensions → CryptoChef.
 */
public final class ContextMenuProvider implements ContextMenuItemsProvider {

    private final MontoyaApi api;
    private final ConfigStore store;
    private final ScopeMatcher scope;

    public ContextMenuProvider(MontoyaApi api, ConfigStore store) {
        this.api = api;
        this.store = store;
        this.scope = new ScopeMatcher(api);
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> items = new ArrayList<>();

        JMenuItem decryptSel  = menuItem("Decrypt selection",  e -> runOnSelection(event, true));
        JMenuItem encryptSel  = menuItem("Encrypt selection",  e -> runOnSelection(event, false));
        JMenuItem decryptBody = menuItem("Decrypt body",       e -> runOnBody(event, true));
        JMenuItem encryptBody = menuItem("Encrypt body",       e -> runOnBody(event, false));
        JMenuItem copyDec     = menuItem("Copy decrypted body to clipboard", e -> copyDecryptedToClipboard(event));
        JMenuItem sendScratch = menuItem("Send decrypted body to scratch window", e -> sendToScratch(event));

        JMenu sub = new JMenu("CryptoChef");
        sub.add(decryptSel);
        sub.add(encryptSel);
        sub.addSeparator();
        sub.add(decryptBody);
        sub.add(encryptBody);
        sub.addSeparator();
        sub.add(copyDec);
        sub.add(sendScratch);

        items.add(sub);
        return items;
    }

    private static JMenuItem menuItem(String label, ActionListener action) {
        JMenuItem mi = new JMenuItem(label);
        mi.addActionListener(action);
        return mi;
    }

    // ==================== handlers ====================

    private void runOnSelection(ContextMenuEvent event, boolean decrypt) {
        Optional<MessageEditorHttpRequestResponse> mo = event.messageEditorRequestResponse();
        if (mo.isEmpty()) { msg("No active message editor."); return; }
        MessageEditorHttpRequestResponse me = mo.get();
        Optional<Range> selOpt = me.selectionOffsets();
        if (selOpt.isEmpty()) { runOnBody(event, decrypt); return; }
        Range sel = selOpt.get();
        HttpRequestResponse pair = me.requestResponse();
        boolean responseEditor = me.selectionContext() == MessageEditorHttpRequestResponse.SelectionContext.RESPONSE;

        Pipeline p = resolvePipeline(pair);
        if (p == null) { msg("No pipeline matches this message's scope."); return; }

        try {
            if (responseEditor) {
                byte[] raw = pair.response().toByteArray().getBytes();
                byte[] slice = java.util.Arrays.copyOfRange(raw, sel.startIndexInclusive(), sel.endIndexExclusive());
                byte[] out = decrypt ? p.decrypt(slice) : p.encrypt(slice);
                byte[] spliced = BodyLocator.spliceBytes(raw, sel.startIndexInclusive(), sel.endIndexExclusive(), out);
                me.setResponse(HttpResponse.httpResponse(ByteArray.byteArray(spliced)));
            } else {
                byte[] raw = pair.request().toByteArray().getBytes();
                byte[] slice = java.util.Arrays.copyOfRange(raw, sel.startIndexInclusive(), sel.endIndexExclusive());
                byte[] out = decrypt ? p.decrypt(slice) : p.encrypt(slice);
                byte[] spliced = BodyLocator.spliceBytes(raw, sel.startIndexInclusive(), sel.endIndexExclusive(), out);
                me.setRequest(HttpRequest.httpRequest(pair.request().httpService(), ByteArray.byteArray(spliced)));
            }
        } catch (Exception e) {
            msg("CryptoChef: " + e.getMessage());
            api.logging().logToError("[CryptoChef] selection transform failed: " + e);
        }
    }

    private void runOnBody(ContextMenuEvent event, boolean decrypt) {
        Optional<MessageEditorHttpRequestResponse> mo = event.messageEditorRequestResponse();
        if (mo.isEmpty()) { msg("No active message editor."); return; }
        MessageEditorHttpRequestResponse me = mo.get();
        HttpRequestResponse pair = me.requestResponse();
        boolean responseEditor = me.selectionContext() == MessageEditorHttpRequestResponse.SelectionContext.RESPONSE;
        Pipeline p = resolvePipeline(pair);
        if (p == null) { msg("No pipeline matches this message's scope."); return; }
        Config.BodyLocation loc = resolveLocation(pair);

        try {
            if (responseEditor) {
                HttpResponse res = pair.response();
                BodyLocator.Extract ex = BodyLocator.extractFromResponse(res, loc);
                if (ex == null) { msg("Could not extract ciphertext."); return; }
                if (decrypt && CryptoHeuristics.looksLikePlaintext(ex.ciphertext)) {
                    msg("Body at ciphertext location already looks like plaintext — skipping decrypt.");
                    return;
                }
                if (!decrypt && CryptoHeuristics.looksLikeCiphertext(ex.ciphertext)) {
                    msg("Body at ciphertext location already looks like ciphertext — skipping encrypt.");
                    return;
                }
                byte[] out = decrypt ? p.decrypt(ex.ciphertext) : p.encrypt(ex.ciphertext);
                me.setResponse(BodyLocator.reinsertIntoResponse(res, loc, out, ex));
            } else {
                HttpRequest req = pair.request();
                BodyLocator.Extract ex = BodyLocator.extractFromRequest(req, loc);
                if (ex == null) { msg("Could not extract ciphertext."); return; }
                if (decrypt && CryptoHeuristics.looksLikePlaintext(ex.ciphertext)) {
                    msg("Body at ciphertext location already looks like plaintext — skipping decrypt.");
                    return;
                }
                if (!decrypt && CryptoHeuristics.looksLikeCiphertext(ex.ciphertext)) {
                    msg("Body at ciphertext location already looks like ciphertext — skipping encrypt.");
                    return;
                }
                byte[] out = decrypt ? p.decrypt(ex.ciphertext) : p.encrypt(ex.ciphertext);
                me.setRequest(BodyLocator.reinsertIntoRequest(req, loc, out, ex));
            }
        } catch (Exception e) {
            msg("CryptoChef: " + e.getMessage());
            api.logging().logToError("[CryptoChef] body transform failed: " + e);
        }
    }

    private void copyDecryptedToClipboard(ContextMenuEvent event) {
        Optional<MessageEditorHttpRequestResponse> mo = event.messageEditorRequestResponse();
        if (mo.isEmpty()) { msg("No active message editor."); return; }
        MessageEditorHttpRequestResponse me = mo.get();
        HttpRequestResponse pair = me.requestResponse();
        Pipeline p = resolvePipeline(pair);
        if (p == null) { msg("No pipeline matches this message's scope."); return; }
        Config.BodyLocation loc = resolveLocation(pair);
        try {
            boolean responseEditor = me.selectionContext() == MessageEditorHttpRequestResponse.SelectionContext.RESPONSE;
            BodyLocator.Extract ex = responseEditor
                    ? BodyLocator.extractFromResponse(pair.response(), loc)
                    : BodyLocator.extractFromRequest(pair.request(), loc);
            if (ex == null) { msg("Could not extract ciphertext."); return; }
            byte[] plain;
            if (CryptoHeuristics.looksLikePlaintext(ex.ciphertext)) {
                plain = ex.ciphertext;
                msg("Body already plaintext — copied raw bytes without decrypt.");
            } else {
                plain = p.decrypt(ex.ciphertext);
                msg("Copied " + plain.length + " bytes of plaintext.");
            }
            String s = new String(plain, StandardCharsets.UTF_8);
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(s), null);
        } catch (Exception e) {
            msg("CryptoChef: " + e.getMessage());
        }
    }

    private void sendToScratch(ContextMenuEvent event) {
        Optional<MessageEditorHttpRequestResponse> mo = event.messageEditorRequestResponse();
        if (mo.isEmpty()) { msg("No active message editor."); return; }
        MessageEditorHttpRequestResponse me = mo.get();
        HttpRequestResponse pair = me.requestResponse();
        Pipeline p = resolvePipeline(pair);
        if (p == null) { msg("No pipeline matches this message's scope."); return; }
        Config.BodyLocation loc = resolveLocation(pair);
        try {
            boolean responseEditor = me.selectionContext() == MessageEditorHttpRequestResponse.SelectionContext.RESPONSE;
            BodyLocator.Extract ex = responseEditor
                    ? BodyLocator.extractFromResponse(pair.response(), loc)
                    : BodyLocator.extractFromRequest(pair.request(), loc);
            if (ex == null) { msg("Could not extract ciphertext."); return; }
            byte[] plain;
            if (CryptoHeuristics.looksLikePlaintext(ex.ciphertext)) {
                plain = ex.ciphertext;
                msg("Body already plaintext — opened raw bytes without decrypt.");
            } else {
                plain = p.decrypt(ex.ciphertext);
            }

            JFrame scratch = new JFrame("CryptoChef — scratch");
            JTextArea ta = new JTextArea(new String(plain, StandardCharsets.UTF_8));
            ta.setLineWrap(true);
            scratch.add(new JScrollPane(ta));
            scratch.setSize(700, 500);
            scratch.setLocationRelativeTo(null);
            scratch.setVisible(true);
        } catch (Exception e) {
            msg("CryptoChef: " + e.getMessage());
        }
    }

    // ==================== helpers ====================

    private Pipeline resolvePipeline(HttpRequestResponse pair) {
        if (pair == null || pair.request() == null) return null;
        Config cfg = store.get();
        String url  = pair.request().url();
        String host = pair.request().httpService() == null ? "" : pair.request().httpService().host();
        Config.NamedPipeline np = scope.pickPipeline(url, host, cfg);
        if (np == null) return null;
        try { return Pipeline.fromConfig(np, cfg); }
        catch (Exception e) {
            api.logging().logToError("[CryptoChef] building pipeline failed: " + e);
            return null;
        }
    }

    private Config.BodyLocation resolveLocation(HttpRequestResponse pair) {
        Config cfg = store.get();
        Config.BodyLocation fallback = new Config.BodyLocation(); // "whole"
        if (pair == null || pair.request() == null) return fallback;
        String url;
        try { url = pair.request().url(); } catch (Exception e) { return fallback; }
        String host = pair.request().httpService() == null ? "" : pair.request().httpService().host();
        ScopeMatcher.Match m = scope.pickMatch(url, host, cfg);
        if (m != null && m.location() != null) return m.location();
        return fallback;
    }

    private void msg(String text) {
        api.logging().logToOutput("[CryptoChef] " + text);
        // No modal — we're on a menu thread and Burp prefers non-blocking feedback.
    }
}
