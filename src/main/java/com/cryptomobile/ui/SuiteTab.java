package com.cryptomobile.ui;

import burp.api.montoya.MontoyaApi;
import com.cryptomobile.config.Config;
import com.cryptomobile.config.ConfigStore;

import javax.swing.*;
import java.awt.*;

/**
 * Root Burp suite tab. Auto decrypt/encrypt is unconditionally on for every
 * supported tool — the panel only exposes per-tool / per-direction toggles
 * for when a tester wants to exclude e.g. Scanner from re-encryption.
 */
public final class SuiteTab extends JPanel {

    private final ConfigStore store;

    private final JCheckBox applyProxy      = new JCheckBox("Proxy");
    private final JCheckBox applyRepeater   = new JCheckBox("Repeater");
    private final JCheckBox applyIntruder   = new JCheckBox("Intruder");
    private final JCheckBox applyLogger     = new JCheckBox("Logger");
    private final JCheckBox applyScanner    = new JCheckBox("Scanner");
    private final JCheckBox applyRequests   = new JCheckBox("Requests");
    private final JCheckBox applyResponses  = new JCheckBox("Responses");

    public SuiteTab(MontoyaApi api, ConfigStore store) {
        super(new BorderLayout(8, 8));
        this.store = store;

        JTabbedPane inner = new JTabbedPane();
        inner.addTab("Pipelines",            safePanel("Pipelines",  () -> new PipelineEditorPanel(store),              api));
        inner.addTab("Key Store",            safePanel("Key Store",  () -> new KeyStorePanel(api, store),               api));
        inner.addTab("Scope rules",          safePanel("Scope",      () -> new ScopePanel(store),                       api));

        add(buildTogglesBar(), BorderLayout.NORTH);
        add(inner, BorderLayout.CENTER);

        // initial sync + listener
        syncFromStore();
        store.addListener(c -> SwingUtilities.invokeLater(this::syncFromStore));
    }

    /** Construct a sub-panel defensively; on failure show the stack trace inside the tab itself. */
    private static JComponent safePanel(String name, java.util.function.Supplier<JComponent> factory, MontoyaApi api) {
        try {
            return factory.get();
        } catch (Throwable t) {
            api.logging().logToError("[CryptoChef] " + name + " panel failed to construct: " + t);
            JTextArea ta = new JTextArea();
            ta.setEditable(false);
            java.io.StringWriter sw = new java.io.StringWriter();
            t.printStackTrace(new java.io.PrintWriter(sw));
            ta.setText("Panel '" + name + "' failed to build:\n\n" + sw);
            return new JScrollPane(ta);
        }
    }

    private JPanel buildTogglesBar() {
        JPanel p = new JPanel(new GridLayout(2, 1, 4, 4));
        p.setBorder(BorderFactory.createTitledBorder(
                "Auto decrypt/encrypt is always on. Choose which tools and directions it applies to:"));

        JPanel row1 = new JPanel(new FlowLayout(FlowLayout.LEFT));
        row1.add(new JLabel("Tools: "));
        row1.add(applyProxy); row1.add(applyRepeater); row1.add(applyIntruder); row1.add(applyLogger); row1.add(applyScanner);
        p.add(row1);

        JPanel row2 = new JPanel(new FlowLayout(FlowLayout.LEFT));
        row2.add(new JLabel("Direction: "));
        row2.add(applyRequests); row2.add(applyResponses);
        p.add(row2);

        // Wiring — persist on change.
        applyProxy   .addActionListener(e -> store.update(c -> c.applyToProxy   = applyProxy.isSelected()));
        applyRepeater.addActionListener(e -> store.update(c -> c.applyToRepeater= applyRepeater.isSelected()));
        applyIntruder.addActionListener(e -> store.update(c -> c.applyToIntruder= applyIntruder.isSelected()));
        applyLogger  .addActionListener(e -> store.update(c -> c.applyToLogger  = applyLogger.isSelected()));
        applyScanner .addActionListener(e -> store.update(c -> c.applyToScanner = applyScanner.isSelected()));
        applyRequests.addActionListener(e -> store.update(c -> c.applyToRequests= applyRequests.isSelected()));
        applyResponses.addActionListener(e -> store.update(c -> c.applyToResponses= applyResponses.isSelected()));
        return p;
    }

    public void syncFromStore() {
        Config c = store.get();
        applyProxy.setSelected(c.applyToProxy);
        applyRepeater.setSelected(c.applyToRepeater);
        applyIntruder.setSelected(c.applyToIntruder);
        applyLogger.setSelected(c.applyToLogger);
        applyScanner.setSelected(c.applyToScanner);
        applyRequests.setSelected(c.applyToRequests);
        applyResponses.setSelected(c.applyToResponses);
    }
}
