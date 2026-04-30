package com.cryptomobile.ui;

import com.cryptomobile.config.Config;
import com.cryptomobile.config.ConfigStore;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.EmptyBorder;
import javax.swing.event.TableModelEvent;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableColumn;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Scope rules editor.
 *
 * <p>Each rule binds a host/URL pattern to a named pipeline and to the body
 * location where the ciphertext lives in that traffic. There is no longer a
 * separate "default ciphertext location" — every rule carries its own
 * location, defaulting to {@code whole} (the entire HTTP body).
 *
 * <p>UX:
 * <ul>
 *   <li>Click <b>Add rule…</b> to open the rule editor with a sensible draft
 *       (wildcard match, {@code *.example.com}, first available pipeline,
 *       {@code whole} body location).</li>
 *   <li>Double-click any row, or use <b>Edit rule…</b>, to open the same
 *       editor pre-filled with the row's values.</li>
 *   <li>The table itself is editable in-place: enabled checkbox, match kind,
 *       host pattern, pipeline, location kind, and location expression.
 *       Edits commit on Enter or focus-out.</li>
 *   <li>Persistence is automatic on every commit — no Save button.</li>
 * </ul>
 */
public final class ScopePanel extends JPanel {

    private static final String[] MATCH_KINDS = { "wildcard", "regex", "burp-target" };
    private static final String[] LOC_KINDS   = { "whole", "header", "regex" };

    private final ConfigStore store;

    private final ScopeTableModel scopeModel = new ScopeTableModel();
    private final JTable scopeTable = new JTable(scopeModel);

    private boolean suppressModelEvents = false;

    public ScopePanel(ConfigStore store) {
        super(new BorderLayout(12, 12));
        this.store = store;
        setBorder(new EmptyBorder(12, 12, 12, 12));

        add(buildScopeCard(), BorderLayout.CENTER);

        store.addListener(cfg -> SwingUtilities.invokeLater(this::refresh));
        refresh();
    }

    // ============================== Scope card ===============================
    private JComponent buildScopeCard() {
        JPanel card = card("Scope rules — each rule bundles host + pipeline + body location");

        JLabel lead = new JLabel("<html>Each rule binds a host or URL pattern to one of your pipelines and "
                + "tells CryptoChef where the ciphertext lives in the message. Double-click a row "
                + "(or use <b>Edit rule…</b>) for the full form. In-line edits commit on Enter / focus-out.</html>");
        lead.setForeground(new Color(0xB0B0B0));

        scopeTable.setFillsViewportHeight(true);
        scopeTable.setRowHeight(26);
        scopeTable.setShowGrid(true);
        scopeTable.setIntercellSpacing(new Dimension(1, 1));
        scopeTable.getTableHeader().setReorderingAllowed(false);
        // Make sure clicking outside an open editor commits the value rather
        // than silently discarding the edit (Swing default is to cancel).
        scopeTable.putClientProperty("terminateEditOnFocusLost", Boolean.TRUE);
        scopeTable.setSurrendersFocusOnKeystroke(true);
        scopeTable.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);

        // Combo cell editors. heavyCombo() disables lightweight popups so the
        // dropdowns render correctly inside Burp's nested AWT host.
        scopeTable.getColumnModel().getColumn(1).setCellEditor(new DefaultCellEditor(heavyCombo(MATCH_KINDS)));
        scopeTable.getColumnModel().getColumn(4).setCellEditor(new DefaultCellEditor(heavyCombo(LOC_KINDS)));
        refreshPipelineColumnEditor();

        // Column widths
        scopeTable.getColumnModel().getColumn(0).setMaxWidth(48);
        scopeTable.getColumnModel().getColumn(0).setMinWidth(48);
        scopeTable.getColumnModel().getColumn(1).setPreferredWidth(110);
        scopeTable.getColumnModel().getColumn(1).setMaxWidth(140);
        scopeTable.getColumnModel().getColumn(2).setPreferredWidth(260);
        scopeTable.getColumnModel().getColumn(3).setPreferredWidth(140);
        scopeTable.getColumnModel().getColumn(4).setPreferredWidth(110);
        scopeTable.getColumnModel().getColumn(4).setMaxWidth(140);
        scopeTable.getColumnModel().getColumn(5).setPreferredWidth(220);

        // Double-click opens the edit dialog
        scopeTable.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override public void mouseClicked(java.awt.event.MouseEvent e) {
                if (e.getClickCount() == 2) {
                    int r = scopeTable.rowAtPoint(e.getPoint());
                    if (r >= 0) openEditRuleDialog(r);
                }
            }
        });

        JScrollPane sp = new JScrollPane(scopeTable);
        sp.setPreferredSize(new Dimension(0, 320));

        JButton addBtn  = new JButton("➕  Add rule…");
        JButton editBtn = new JButton("Edit rule…");
        JButton delBtn  = new JButton("Remove selected");

        addBtn.putClientProperty("JButton.buttonType", "roundRect");
        addBtn.setFont(addBtn.getFont().deriveFont(Font.BOLD));

        JPanel btns = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        btns.setOpaque(false);
        btns.add(addBtn);
        btns.add(editBtn);
        btns.add(Box.createHorizontalStrut(16));
        btns.add(delBtn);

        addBtn.addActionListener(e -> openAddRuleDialog());
        editBtn.addActionListener(e -> {
            int r = scopeTable.getSelectedRow();
            if (r < 0) {
                JOptionPane.showMessageDialog(this, "Select a row first.");
                return;
            }
            openEditRuleDialog(r);
        });
        delBtn.addActionListener(e -> {
            int r = scopeTable.getSelectedRow();
            if (r < 0) {
                JOptionPane.showMessageDialog(this, "Select a row first.");
                return;
            }
            // Confirm so users don't lose a rule by mis-clicking.
            String pattern = String.valueOf(scopeModel.getValueAt(r, 2));
            int ans = JOptionPane.showConfirmDialog(this,
                    "Remove rule for '" + pattern + "'?", "Confirm removal",
                    JOptionPane.OK_CANCEL_OPTION);
            if (ans != JOptionPane.OK_OPTION) return;
            final int row = r;
            store.update(cfg -> { if (row < cfg.scopeRules.size()) cfg.scopeRules.remove(row); });
            refresh();
        });

        // In-line table edits → persist via store.update.
        scopeModel.addTableModelListener(e -> {
            if (suppressModelEvents) return;
            if (e.getType() != TableModelEvent.UPDATE) return;
            int row = e.getFirstRow();
            int col = e.getColumn();
            if (row < 0 || col < 0) return;
            if (row >= scopeModel.getRowCount()) return;
            Object v = scopeModel.getValueAt(row, col);
            store.update(cfg -> {
                if (row >= cfg.scopeRules.size()) return;
                Config.ScopeRule rule = cfg.scopeRules.get(row);
                if (rule.bodyLocation == null) rule.bodyLocation = new Config.BodyLocation();
                switch (col) {
                    case 0 -> rule.enabled      = Boolean.TRUE.equals(v);
                    case 1 -> rule.matchKind    = String.valueOf(v);
                    case 2 -> rule.pattern      = String.valueOf(v);
                    case 3 -> rule.pipelineName = String.valueOf(v);
                    case 4 -> rule.bodyLocation.kind = String.valueOf(v);
                    case 5 -> rule.bodyLocation.expression = String.valueOf(v);
                }
            });
        });

        card.add(lead);
        card.add(Box.createVerticalStrut(10));
        card.add(sp);
        card.add(Box.createVerticalStrut(8));
        card.add(btns);
        return card;
    }

    // ---- Add / Edit rule dialog (shared form) ----

    private void openAddRuleDialog() {
        List<String> pipelineNames = pipelineNames();
        if (pipelineNames.isEmpty()) {
            JOptionPane.showMessageDialog(this,
                    "You have no pipelines yet.\nCreate one in the Pipelines tab first, then come back here to bind it to a host.",
                    "No pipelines", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        Config.ScopeRule draft = new Config.ScopeRule("wildcard", "*.example.com", pipelineNames.get(0));
        draft.bodyLocation = new Config.BodyLocation("whole", "");
        if (showRuleDialog("New scope rule", draft, pipelineNames)) {
            store.update(cfg -> cfg.scopeRules.add(draft));
            refresh();
        }
    }

    private void openEditRuleDialog(int row) {
        Config cfg = store.get();
        if (row < 0 || row >= cfg.scopeRules.size()) return;
        List<String> pipelineNames = pipelineNames();
        if (pipelineNames.isEmpty()) pipelineNames = List.of("");

        Config.ScopeRule orig = cfg.scopeRules.get(row);
        Config.ScopeRule draft = new Config.ScopeRule(orig.matchKind, orig.pattern, orig.pipelineName);
        draft.enabled = orig.enabled;
        if (orig.bodyLocation != null) {
            draft.bodyLocation = new Config.BodyLocation(orig.bodyLocation.kind, orig.bodyLocation.expression);
        } else {
            draft.bodyLocation = new Config.BodyLocation("whole", "");
        }

        if (showRuleDialog("Edit scope rule", draft, pipelineNames)) {
            store.update(c -> {
                if (row >= c.scopeRules.size()) return;
                Config.ScopeRule r = c.scopeRules.get(row);
                r.enabled      = draft.enabled;
                r.matchKind    = draft.matchKind;
                r.pattern      = draft.pattern;
                r.pipelineName = draft.pipelineName;
                r.bodyLocation = draft.bodyLocation == null
                        ? new Config.BodyLocation()
                        : new Config.BodyLocation(draft.bodyLocation.kind, draft.bodyLocation.expression);
            });
            refresh();
        }
    }

    /** Returns true if the user clicked Apply. Mutates {@code draft} in place. */
    private boolean showRuleDialog(String title, Config.ScopeRule draft, List<String> pipelineNames) {
        JComboBox<String> kind = heavyCombo(MATCH_KINDS);
        kind.setSelectedItem(draft.matchKind == null ? "wildcard" : draft.matchKind);
        JTextField host = new JTextField(draft.pattern == null ? "" : draft.pattern, 28);
        JComboBox<String> pipe = heavyCombo(pipelineNames.toArray(new String[0]));
        if (draft.pipelineName != null) pipe.setSelectedItem(draft.pipelineName);

        JComboBox<String> locKind = heavyCombo(LOC_KINDS);
        JTextField locExpr = new JTextField(28);
        String dKind = (draft.bodyLocation != null && draft.bodyLocation.kind != null && !draft.bodyLocation.kind.isBlank())
                ? draft.bodyLocation.kind : "whole";
        locKind.setSelectedItem(dKind);
        locExpr.setText(draft.bodyLocation == null || draft.bodyLocation.expression == null
                ? "" : draft.bodyLocation.expression);

        JLabel kindHint = italic();
        JLabel locHint  = italic();

        Runnable updKind = () -> {
            String k = (String) kind.getSelectedItem();
            if ("wildcard".equals(k)) {
                host.setEnabled(true);
                kindHint.setText("Wildcard over host/URL — e.g. *.example.com or *api.bank.com*");
            } else if ("regex".equals(k)) {
                host.setEnabled(true);
                kindHint.setText("Java regex over the full URL — e.g. https://api\\.bank\\.com/.*");
            } else {
                host.setEnabled(false);
                kindHint.setText("Reuses Burp's Target Scope — pattern is ignored.");
            }
        };
        Runnable updLoc = () -> {
            String k = (String) locKind.getSelectedItem();
            if ("whole".equals(k)) {
                locExpr.setEnabled(false);
                locHint.setText("Entire HTTP body is treated as ciphertext. Expression is ignored.");
            } else if ("header".equals(k)) {
                locExpr.setEnabled(true);
                locHint.setText("Header NAME (case-insensitive), e.g.  X-Payload");
            } else {
                locExpr.setEnabled(true);
                locHint.setText("Java regex. Group 1 (if present) is the ciphertext, else the whole match.");
            }
        };
        kind.addActionListener(e -> updKind.run());
        locKind.addActionListener(e -> updLoc.run());
        updKind.run();
        updLoc.run();

        JCheckBox enabled = new JCheckBox("Enabled", draft.enabled);

        JPanel form = new JPanel(new GridBagLayout());
        GridBagConstraints g = gbc();
        int y = 0;
        g.gridy = y; g.gridx = 0; form.add(enabled, g);
        g.gridy = ++y; g.gridx = 0; form.add(new JLabel("Match kind:"), g);
        g.gridx = 1; g.weightx = 1; form.add(kind, g);
        g.gridy = ++y; g.gridx = 0; g.weightx = 0; form.add(new JLabel("Host / URL:"), g);
        g.gridx = 1; g.weightx = 1; form.add(host, g);
        g.gridy = ++y; g.gridx = 1; form.add(kindHint, g);
        g.gridy = ++y; g.gridx = 0; g.weightx = 0; form.add(new JLabel("Pipeline:"), g);
        g.gridx = 1; g.weightx = 1; form.add(pipe, g);
        g.gridy = ++y; g.gridx = 0; g.weightx = 0;
        form.add(Box.createVerticalStrut(8), g);
        g.gridy = ++y; g.gridx = 0; g.weightx = 0; form.add(new JLabel("Body location:"), g);
        g.gridx = 1; g.weightx = 1; form.add(locKind, g);
        g.gridy = ++y; g.gridx = 0; g.weightx = 0; form.add(new JLabel("Expression:"), g);
        g.gridx = 1; g.weightx = 1; form.add(locExpr, g);
        g.gridy = ++y; g.gridx = 1; form.add(locHint, g);

        JButton applyBtn  = new JButton("Apply");
        JButton cancelBtn = new JButton("Cancel");
        applyBtn.putClientProperty("JButton.buttonType", "roundRect");
        applyBtn.setFont(applyBtn.getFont().deriveFont(Font.BOLD));

        final boolean[] applied = { false };
        final JDialog[] dlgRef = { null };

        applyBtn.addActionListener(e -> {
            String pat = host.getText().trim();
            String mk  = (String) kind.getSelectedItem();
            // burp-target ignores the pattern; otherwise require something.
            if (!"burp-target".equals(mk) && pat.isEmpty()) {
                JOptionPane.showMessageDialog(dlgRef[0], "Enter a host/URL pattern.",
                        "Pattern required", JOptionPane.WARNING_MESSAGE);
                return;
            }
            String pn = (String) pipe.getSelectedItem();
            if (pn == null || pn.isBlank()) {
                JOptionPane.showMessageDialog(dlgRef[0], "Pick a pipeline.",
                        "Pipeline required", JOptionPane.WARNING_MESSAGE);
                return;
            }
            String lk = (String) locKind.getSelectedItem();
            if (lk == null || lk.isBlank()) lk = "whole";
            if (("header".equals(lk) || "regex".equals(lk)) && locExpr.getText().trim().isEmpty()) {
                JOptionPane.showMessageDialog(dlgRef[0],
                        "Enter " + ("header".equals(lk) ? "a header name." : "a regex."),
                        "Expression required", JOptionPane.WARNING_MESSAGE);
                return;
            }
            draft.enabled      = enabled.isSelected();
            draft.matchKind    = mk;
            draft.pattern      = pat;
            draft.pipelineName = pn;
            if (draft.bodyLocation == null) draft.bodyLocation = new Config.BodyLocation();
            draft.bodyLocation.kind = lk;
            draft.bodyLocation.expression = locExpr.getText().trim();
            applied[0] = true;
            if (dlgRef[0] != null) dlgRef[0].dispose();
        });
        cancelBtn.addActionListener(e -> { if (dlgRef[0] != null) dlgRef[0].dispose(); });

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        buttons.setOpaque(false);
        buttons.add(cancelBtn);
        buttons.add(applyBtn);

        JPanel root = new JPanel(new BorderLayout(0, 10));
        root.setBorder(new EmptyBorder(12, 12, 12, 12));
        root.add(form, BorderLayout.CENTER);
        root.add(buttons, BorderLayout.SOUTH);

        Window owner = SwingUtilities.getWindowAncestor(this);
        JDialog dlg = new JDialog(owner, title, Dialog.ModalityType.APPLICATION_MODAL);
        dlgRef[0] = dlg;
        dlg.getRootPane().setDefaultButton(applyBtn);
        dlg.setContentPane(root);
        dlg.pack();
        dlg.setLocationRelativeTo(owner);
        dlg.setVisible(true);
        return applied[0];
    }

    private static JLabel italic() {
        JLabel l = new JLabel(" ");
        l.setFont(l.getFont().deriveFont(Font.ITALIC, 11f));
        l.setForeground(new Color(0x999999));
        return l;
    }

    // ============================== helpers ==============================
    public void refresh() {
        suppressModelEvents = true;
        try {
            Config cfg = store.get();
            scopeModel.setRules(cfg == null || cfg.scopeRules == null
                    ? java.util.Collections.emptyList() : cfg.scopeRules);
            refreshPipelineColumnEditor();
        } finally {
            suppressModelEvents = false;
        }
    }

    private List<String> pipelineNames() {
        Config cfg = store.get();
        List<String> names = new ArrayList<>();
        if (cfg.pipelines != null) for (Config.NamedPipeline p : cfg.pipelines) if (p.name != null) names.add(p.name);
        return names;
    }

    private void refreshPipelineColumnEditor() {
        List<String> names = pipelineNames();
        if (names.isEmpty()) names = List.of("");
        JComboBox<String> combo = heavyCombo(names.toArray(new String[0]));
        TableColumn col = scopeTable.getColumnModel().getColumn(3);
        col.setCellEditor(new DefaultCellEditor(combo));
    }

    private static JComboBox<String> heavyCombo(String[] items) {
        JComboBox<String> c = new JComboBox<>(items);
        c.setLightWeightPopupEnabled(false);
        return c;
    }

    /** Titled card container, BoxLayout Y_AXIS. */
    private static JPanel card(String title) {
        JPanel p = new JPanel();
        p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
        Border titled = BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(new Color(0x4A4A4A), 1, true),
                "  " + title + "  ",
                javax.swing.border.TitledBorder.LEFT,
                javax.swing.border.TitledBorder.TOP);
        Border padding = new EmptyBorder(10, 14, 14, 14);
        p.setBorder(BorderFactory.createCompoundBorder(titled, padding));
        p.setAlignmentX(Component.LEFT_ALIGNMENT);
        return p;
    }

    private static GridBagConstraints gbc() {
        GridBagConstraints g = new GridBagConstraints();
        g.insets = new Insets(4, 6, 4, 6);
        g.fill = GridBagConstraints.HORIZONTAL;
        g.anchor = GridBagConstraints.WEST;
        return g;
    }

    // =========================== Table model ============================
    private static class ScopeTableModel extends AbstractTableModel {
        private List<Config.ScopeRule> rules = java.util.Collections.emptyList();
        void setRules(List<Config.ScopeRule> r) {
            rules = r == null ? java.util.Collections.emptyList() : r;
            fireTableDataChanged();
        }
        @Override public int getRowCount()    { return rules.size(); }
        @Override public int getColumnCount() { return 6; }
        @Override public String getColumnName(int c) {
            return switch (c) {
                case 0 -> "On";
                case 1 -> "Match";
                case 2 -> "Host / URL / regex";
                case 3 -> "Pipeline";
                case 4 -> "Location";
                case 5 -> "Expression";
                default -> "";
            };
        }
        @Override public Class<?> getColumnClass(int c) { return c == 0 ? Boolean.class : String.class; }
        @Override public boolean isCellEditable(int r, int c) { return true; }
        @Override public Object getValueAt(int r, int c) {
            if (r < 0 || r >= rules.size() || c < 0) return null;
            Config.ScopeRule rule = rules.get(r);
            return switch (c) {
                case 0 -> rule.enabled;
                case 1 -> rule.matchKind;
                case 2 -> rule.pattern;
                case 3 -> rule.pipelineName;
                case 4 -> (rule.bodyLocation == null || rule.bodyLocation.kind == null || rule.bodyLocation.kind.isBlank())
                        ? "whole" : rule.bodyLocation.kind;
                case 5 -> rule.bodyLocation == null ? "" : (rule.bodyLocation.expression == null ? "" : rule.bodyLocation.expression);
                default -> null;
            };
        }
        @Override public void setValueAt(Object v, int r, int c) {
            if (r < 0 || r >= rules.size() || c < 0) return;
            Config.ScopeRule rule = rules.get(r);
            if (rule.bodyLocation == null) rule.bodyLocation = new Config.BodyLocation();
            switch (c) {
                case 0 -> rule.enabled = Boolean.TRUE.equals(v);
                case 1 -> rule.matchKind = String.valueOf(v);
                case 2 -> rule.pattern = String.valueOf(v);
                case 3 -> rule.pipelineName = String.valueOf(v);
                case 4 -> {
                    String kk = String.valueOf(v);
                    rule.bodyLocation.kind = (kk == null || kk.isBlank()) ? "whole" : kk;
                }
                case 5 -> rule.bodyLocation.expression = String.valueOf(v);
            }
            fireTableCellUpdated(r, c);
        }
    }
}
