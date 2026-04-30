package com.cryptomobile;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import burp.api.montoya.ui.editor.extension.HttpRequestEditorProvider;
import burp.api.montoya.ui.editor.extension.HttpResponseEditorProvider;
import com.cryptomobile.config.ConfigStore;
import com.cryptomobile.http.CryptoHttpHandler;
import com.cryptomobile.http.CryptoProxyRequestHandler;
import com.cryptomobile.http.CryptoProxyResponseHandler;
import com.cryptomobile.ui.ContextMenuProvider;
import com.cryptomobile.ui.DecryptedRequestEditor;
import com.cryptomobile.ui.DecryptedResponseEditor;
import com.cryptomobile.ui.SuiteTab;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.security.Security;

/**
 * Burp entry point. Wires the config store, crypto pipeline factory, HTTP
 * handler, context menu, message editors, and suite tab.
 */
public final class CryptoChefExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("CryptoChef");
        api.logging().logToOutput("[CryptoChef] initialize() starting...");

        // Install BouncyCastle once (Nimbus and some algorithms rely on it).
        if (Security.getProvider("BC") == null) {
            try {
                Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            } catch (Throwable t) {
                api.logging().logToError("[CryptoChef] could not register BouncyCastle: " + t);
            }
        }

        ConfigStore store;
        try {
            store = new ConfigStore(api);
            api.logging().logToOutput("[CryptoChef] config store ready.");
        } catch (Throwable t) {
            api.logging().logToError("[CryptoChef] FATAL: could not build ConfigStore: " + stack(t));
            return;
        }

        // F4 — HTTP handler for auto mode (covers Repeater/Intruder/Scanner/etc.
        //        + wire-side encrypt/decrypt for proxy traffic).
        try {
            api.http().registerHttpHandler(new CryptoHttpHandler(api, store));
            api.logging().logToOutput("[CryptoChef] HTTP handler registered.");
        } catch (Throwable t) {
            api.logging().logToError("[CryptoChef] HTTP handler registration failed: " + stack(t));
        }

        // F4b — proxy-side handlers so the proxy intercept view and HTTP history
        //        show plaintext for proxied app traffic, while the wire still
        //        carries valid ciphertext in both directions.
        try {
            api.proxy().registerRequestHandler(new CryptoProxyRequestHandler(api, store));
            api.proxy().registerResponseHandler(new CryptoProxyResponseHandler(api, store));
            api.logging().logToOutput("[CryptoChef] proxy handlers registered.");
        } catch (Throwable t) {
            api.logging().logToError("[CryptoChef] proxy handler registration failed: " + stack(t));
        }

        // F2 — context menu
        try {
            api.userInterface().registerContextMenuItemsProvider(new ContextMenuProvider(api, store));
            api.logging().logToOutput("[CryptoChef] context menu registered.");
        } catch (Throwable t) {
            api.logging().logToError("[CryptoChef] context menu registration failed: " + stack(t));
        }

        // F1 — decrypted editor tabs
        try {
            api.userInterface().registerHttpRequestEditorProvider(new HttpRequestEditorProvider() {
                @Override
                public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(EditorCreationContext ctx) {
                    return new DecryptedRequestEditor(api, store, ctx);
                }
            });
            api.userInterface().registerHttpResponseEditorProvider(new HttpResponseEditorProvider() {
                @Override
                public ExtensionProvidedHttpResponseEditor provideHttpResponseEditor(EditorCreationContext ctx) {
                    return new DecryptedResponseEditor(api, store, ctx);
                }
            });
            api.logging().logToOutput("[CryptoChef] message editors registered.");
        } catch (Throwable t) {
            api.logging().logToError("[CryptoChef] message editor registration failed: " + stack(t));
        }

        // F3 — suite tab. Register an empty shell FIRST so Burp always draws
        // the tab, then populate it. If the real SuiteTab throws, the user
        // still sees a "CryptoChef" tab with the error in it.
        javax.swing.JPanel shell = new javax.swing.JPanel(new java.awt.BorderLayout());
        shell.add(new javax.swing.JLabel("CryptoChef — initializing…"), java.awt.BorderLayout.CENTER);
        try {
            api.userInterface().registerSuiteTab("CryptoChef", shell);
            api.logging().logToOutput("[CryptoChef] suite-tab shell registered.");
        } catch (Throwable t) {
            api.logging().logToError("[CryptoChef] FAILED to register suite-tab shell: " + stack(t));
        }
        try {
            SuiteTab tab = new SuiteTab(api, store);
            shell.removeAll();
            shell.add(tab, java.awt.BorderLayout.CENTER);
            shell.revalidate();
            shell.repaint();
            api.logging().logToOutput("[CryptoChef] suite tab populated — click the 'CryptoChef' tab at the top.");
        } catch (Throwable t) {
            api.logging().logToError("[CryptoChef] SuiteTab populate failed: " + stack(t));
            java.io.StringWriter sw = new java.io.StringWriter();
            t.printStackTrace(new java.io.PrintWriter(sw));
            javax.swing.JTextArea err = new javax.swing.JTextArea(sw.toString());
            err.setEditable(false);
            shell.removeAll();
            shell.add(new javax.swing.JScrollPane(err), java.awt.BorderLayout.CENTER);
        }

        api.extension().registerUnloadingHandler(() -> api.logging().logToOutput("[CryptoChef] unloading."));
        api.logging().logToOutput("[CryptoChef] loaded. Open the 'CryptoChef' tab to configure pipelines.");
    }

    private static String stack(Throwable t) {
        StringWriter sw = new StringWriter();
        t.printStackTrace(new PrintWriter(sw));
        return sw.toString();
    }
}
