package com.cryptomobile.ui;

import com.cryptomobile.config.Config;
import com.cryptomobile.config.ConfigStore;
import com.cryptomobile.crypto.Pipeline;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * F3.1 — Pipeline Builder UI.
 *
 * <p>Left: list of named pipelines (add/rename/remove). Right: the selected
 * pipeline's step table with up/down/add/remove and an "Edit step" dialog.
 * Bottom: "Test pipeline" area with stage-by-stage trace.
 */
public final class PipelineEditorPanel extends JPanel {

    private static final String[] TYPES = {
            "AES-256-CBC", "AES-128-CBC", "AES-256-GCM", "AES-256-ECB",
            "RSA-OAEP-HYBRID", "JWE", "XOR", "BASE64"
    };

    private static final String[] ENCODINGS   = {"hex", "utf-8", "base64"};
    private static final String[] IO_FORMATS  = {"raw", "hex", "base64"};

    private final ConfigStore store;
    private final DefaultListModel<String> pipelineListModel = new DefaultListModel<>();
    private final JList<String> pipelineList = new JList<>(pipelineListModel);
    private final StepTableModel stepModel = new StepTableModel();
    private final JTable stepTable = new JTable(stepModel);
    private final JTextArea testInput  = new JTextArea(4, 40);
    private final JTextArea testOutput = new JTextArea(6, 40);
    private final JComboBox<String> testDirection = heavyCombo("decrypt", "encrypt");
    private final JComboBox<String> testInputEncoding = heavyCombo("utf-8", "hex", "base64");

    private static JComboBox<String> heavyCombo(String... items) {
        JComboBox<String> c = new JComboBox<>(items);
        c.setLightWeightPopupEnabled(false);
        return c;
    }

    public PipelineEditorPanel(ConfigStore store) {
        super(new BorderLayout(8, 8));
        this.store = store;

        JPanel left = new JPanel(new BorderLayout(4, 4));
        left.setBorder(BorderFactory.createTitledBorder("Pipelines"));
        left.add(new JScrollPane(pipelineList), BorderLayout.CENTER);
        JPanel leftBtns = new JPanel(new GridLayout(1, 3, 4, 4));
        JButton addPipe = new JButton("New");
        JButton renPipe = new JButton("Rename");
        JButton delPipe = new JButton("Delete");
        leftBtns.add(addPipe); leftBtns.add(renPipe); leftBtns.add(delPipe);
        left.add(leftBtns, BorderLayout.SOUTH);
        left.setPreferredSize(new Dimension(200, 0));

        JPanel right = new JPanel(new BorderLayout(4, 4));
        right.setBorder(BorderFactory.createTitledBorder("Steps (top runs first on encrypt; bottom runs first on decrypt)"));
        // Make sure clicking outside an open editor commits the value rather
        // than silently cancelling — Swing's default is to discard.
        stepTable.putClientProperty("terminateEditOnFocusLost", Boolean.TRUE);
        stepTable.setSurrendersFocusOnKeystroke(true);
        right.add(new JScrollPane(stepTable), BorderLayout.CENTER);

        // Double-click any step row → open the edit dialog.
        stepTable.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override public void mouseClicked(java.awt.event.MouseEvent ev) {
                if (ev.getClickCount() == 2 && stepTable.getSelectedRow() >= 0) {
                    editStepDialog();
                }
            }
        });
        JPanel rightBtns = new JPanel(new GridLayout(1, 5, 4, 4));
        JButton addStep = new JButton("Add step");
        JButton editStep= new JButton("Edit step");
        JButton delStep = new JButton("Remove step");
        JButton upStep  = new JButton("\u25B2");
        JButton dnStep  = new JButton("\u25BC");
        rightBtns.add(addStep); rightBtns.add(editStep); rightBtns.add(delStep); rightBtns.add(upStep); rightBtns.add(dnStep);
        right.add(rightBtns, BorderLayout.SOUTH);

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, left, right);
        split.setResizeWeight(0.20);

        JPanel bottom = new JPanel(new BorderLayout(4, 4));
        bottom.setBorder(BorderFactory.createTitledBorder("Test pipeline"));
        JPanel testTop = new JPanel(new FlowLayout(FlowLayout.LEFT));
        testTop.add(new JLabel("Input encoding:"));
        testTop.add(testInputEncoding);
        testTop.add(new JLabel("Direction:"));
        testTop.add(testDirection);
        JButton runTest = new JButton("Run");
        testTop.add(runTest);
        bottom.add(testTop, BorderLayout.NORTH);
        testInput.setLineWrap(true);  testInput.setWrapStyleWord(false);
        testOutput.setEditable(false); testOutput.setLineWrap(true);
        JSplitPane tsplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(testInput), new JScrollPane(testOutput));
        tsplit.setResizeWeight(0.4);
        bottom.add(tsplit, BorderLayout.CENTER);

        JSplitPane root = new JSplitPane(JSplitPane.VERTICAL_SPLIT, split, bottom);
        root.setResizeWeight(0.6);
        add(root, BorderLayout.CENTER);

        refreshFromStore();

        pipelineList.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) reloadSteps();
        });

        addPipe.addActionListener(e -> {
            String name = JOptionPane.showInputDialog(this, "Pipeline name:");
            if (name == null || name.isBlank()) return;
            final String finalName = name.trim();
            store.update(c -> {
                if (c.findPipeline(finalName) != null) return;
                c.pipelines.add(new Config.NamedPipeline(finalName));
            });
            refreshFromStore();
            pipelineList.setSelectedValue(finalName, true);
        });
        renPipe.addActionListener(e -> {
            String sel = pipelineList.getSelectedValue();
            if (sel == null) { msg("Select a pipeline first."); return; }
            String name = JOptionPane.showInputDialog(this, "New name:", sel);
            if (name == null || name.isBlank() || name.equals(sel)) return;
            final String finalName = name.trim();
            store.update(c -> {
                Config.NamedPipeline p = c.findPipeline(sel);
                if (p == null) return;
                p.name = finalName;
                for (Config.ScopeRule r : c.scopeRules) if (sel.equals(r.pipelineName)) r.pipelineName = finalName;
            });
            refreshFromStore();
            pipelineList.setSelectedValue(finalName, true);
        });
        delPipe.addActionListener(e -> {
            String sel = pipelineList.getSelectedValue();
            if (sel == null) { msg("Select a pipeline first."); return; }
            if (JOptionPane.showConfirmDialog(this, "Delete pipeline '" + sel + "'?", "Confirm",
                    JOptionPane.OK_CANCEL_OPTION) != JOptionPane.OK_OPTION) return;
            store.update(c -> c.pipelines.removeIf(p -> sel.equals(p.name)));
            refreshFromStore();
        });

        addStep.addActionListener(e -> {
            String selPipe = pipelineList.getSelectedValue();
            if (selPipe == null) { msg("Select a pipeline first."); return; }
            StepDialog dlg = new StepDialog(SwingUtilities.getWindowAncestor(this), null);
            dlg.setVisible(true);
            Config.PipelineStep step = dlg.result;
            if (step == null) return;
            store.update(c -> {
                Config.NamedPipeline p = c.findPipeline(selPipe);
                if (p != null) p.steps.add(step);
            });
            reloadSteps();
        });
        editStep.addActionListener(e -> editStepDialog());
        delStep.addActionListener(e -> {
            String selPipe = pipelineList.getSelectedValue();
            int row = stepTable.getSelectedRow();
            if (selPipe == null) { msg("Select a pipeline first."); return; }
            if (row < 0) { msg("Select a step row first."); return; }
            store.update(c -> {
                Config.NamedPipeline p = c.findPipeline(selPipe);
                if (p != null && row < p.steps.size()) p.steps.remove(row);
            });
            reloadSteps();
        });
        upStep.addActionListener(e -> moveStep(-1));
        dnStep.addActionListener(e -> moveStep(+1));

        runTest.addActionListener(e -> runTest());

        stepTable.getModel().addTableModelListener(e -> {
            if (e.getColumn() == 0) {
                String selPipe = pipelineList.getSelectedValue();
                if (selPipe == null) return;
                int row = e.getFirstRow();
                store.update(c -> {
                    Config.NamedPipeline p = c.findPipeline(selPipe);
                    if (p != null && row < p.steps.size()) {
                        p.steps.get(row).enabled = (Boolean) stepModel.getValueAt(row, 0);
                    }
                });
            }
        });

        store.addListener(c -> SwingUtilities.invokeLater(this::refreshFromStore));
    }

    /** Opens the step editor for the currently selected pipeline + step row. */
    private void editStepDialog() {
        String selPipe = pipelineList.getSelectedValue();
        int row = stepTable.getSelectedRow();
        if (selPipe == null) { msg("Select a pipeline first."); return; }
        if (row < 0) { msg("Select a step row first."); return; }
        Config.NamedPipeline np = store.get().findPipeline(selPipe);
        if (np == null || row >= np.steps.size()) return;
        StepDialog dlg = new StepDialog(SwingUtilities.getWindowAncestor(this), np.steps.get(row));
        dlg.setVisible(true);
        Config.PipelineStep step = dlg.result;
        if (step == null) return;
        store.update(c -> {
            Config.NamedPipeline p = c.findPipeline(selPipe);
            if (p != null && row < p.steps.size()) p.steps.set(row, step);
        });
        reloadSteps();
    }

    private void moveStep(int delta) {
        String selPipe = pipelineList.getSelectedValue();
        int row = stepTable.getSelectedRow();
        if (selPipe == null || row < 0) return;
        int[] newRow = {row};
        store.update(c -> {
            Config.NamedPipeline p = c.findPipeline(selPipe);
            if (p == null) return;
            int to = row + delta;
            if (to < 0 || to >= p.steps.size()) return;
            Config.PipelineStep s = p.steps.remove(row);
            p.steps.add(to, s);
            newRow[0] = to;
        });
        reloadSteps();
        stepTable.getSelectionModel().setSelectionInterval(newRow[0], newRow[0]);
    }

    public void refreshFromStore() {
        Config c = store.get();
        String sel = pipelineList.getSelectedValue();
        pipelineListModel.clear();
        for (Config.NamedPipeline p : c.pipelines) pipelineListModel.addElement(p.name);
        if (sel != null && pipelineListModel.contains(sel)) pipelineList.setSelectedValue(sel, true);
        else if (!pipelineListModel.isEmpty()) pipelineList.setSelectedIndex(0);
        reloadSteps();
    }

    private void reloadSteps() {
        String sel = pipelineList.getSelectedValue();
        if (sel == null) { stepModel.setSteps(java.util.Collections.emptyList()); return; }
        Config.NamedPipeline np = store.get().findPipeline(sel);
        stepModel.setSteps(np == null ? java.util.Collections.emptyList() : np.steps);
    }

    private void runTest() {
        String selPipe = pipelineList.getSelectedValue();
        if (selPipe == null) { testOutput.setText("(no pipeline selected)"); return; }
        Config cfg = store.get();
        Config.NamedPipeline np = cfg.findPipeline(selPipe);
        if (np == null) { testOutput.setText("(pipeline not found)"); return; }

        String enc = (String) testInputEncoding.getSelectedItem();
        String dir = (String) testDirection.getSelectedItem();
        byte[] input;
        try {
            input = switch (enc == null ? "utf-8" : enc) {
                case "hex"    -> HexFormat.of().parseHex(testInput.getText().trim().replaceAll("\\s+", ""));
                case "base64" -> com.cryptomobile.crypto.KeyMaterialCodec.decodeBase64Tolerant(testInput.getText().trim());
                default       -> testInput.getText().getBytes(StandardCharsets.UTF_8);
            };
        } catch (Exception e) {
            testOutput.setText("Input decode error: " + e.getMessage());
            return;
        }

        try {
            Pipeline p = Pipeline.fromConfig(np, cfg);
            List<Pipeline.Stage> stages = "decrypt".equals(dir) ? p.decryptWithTrace(input) : p.encryptWithTrace(input);
            StringBuilder sb = new StringBuilder();
            sb.append("Input (").append(enc).append("): ").append(hexPreview(input)).append('\n');
            for (int i = 0; i < stages.size(); i++) {
                Pipeline.Stage s = stages.get(i);
                sb.append('\n').append("Stage ").append(i + 1).append(" \u2014 ").append(s.stepName()).append('\n');
                sb.append("  hex: ").append(hexPreview(s.output())).append('\n');
                sb.append("  utf-8: ").append(safeUtf8(s.output())).append('\n');
            }
            testOutput.setText(sb.toString());
        } catch (Exception e) {
            testOutput.setText("Error: " + e.getMessage());
        }
    }

    private static String hexPreview(byte[] b) {
        int n = Math.min(64, b.length);
        StringBuilder sb = new StringBuilder(HexFormat.of().formatHex(b, 0, n));
        if (b.length > n) sb.append(" \u2026 (").append(b.length).append(" bytes)");
        return sb.toString();
    }

    private static String safeUtf8(byte[] b) {
        String s = new String(b, StandardCharsets.UTF_8);
        if (s.length() > 200) s = s.substring(0, 200) + "\u2026";
        return s.replaceAll("[\\p{Cntrl}&&[^\\r\\n\\t]]", ".");
    }

    private void msg(String text) { JOptionPane.showMessageDialog(this, text); }

    // ==================== inner classes ====================

    private static class StepTableModel extends AbstractTableModel {
        private List<Config.PipelineStep> steps = java.util.Collections.emptyList();
        void setSteps(List<Config.PipelineStep> s) { steps = s; fireTableDataChanged(); }
        @Override public int getRowCount()    { return steps.size(); }
        @Override public int getColumnCount() { return 4; }
        @Override public String getColumnName(int c) {
            return switch (c) { case 0 -> "On"; case 1 -> "Type"; case 2 -> "In \u2192 Out"; default -> "Params"; };
        }
        @Override public Class<?> getColumnClass(int c) { return c == 0 ? Boolean.class : String.class; }
        @Override public boolean isCellEditable(int r, int c) { return c == 0; }
        @Override public Object getValueAt(int r, int c) {
            Config.PipelineStep s = steps.get(r);
            return switch (c) {
                case 0 -> s.enabled;
                case 1 -> s.type;
                case 2 -> ioSummary(s.params);
                default -> paramSummary(s.params);
            };
        }
        @Override public void setValueAt(Object v, int r, int c) {
            if (c == 0) {
                steps.get(r).enabled = Boolean.TRUE.equals(v);
                fireTableCellUpdated(r, c);
            }
        }
        private String ioSummary(Map<String, String> params) {
            if (params == null) return "raw \u2192 raw";
            String in  = params.getOrDefault("input-encoding",  "raw");
            String out = params.getOrDefault("output-encoding", "raw");
            return in + " \u2192 " + out;
        }
        private String paramSummary(Map<String, String> params) {
            if (params == null || params.isEmpty()) return "(none)";
            StringBuilder sb = new StringBuilder();
            params.forEach((k, v) -> {
                if ("input-encoding".equals(k) || "output-encoding".equals(k)) return;
                if (sb.length() > 0) sb.append(", ");
                boolean sensitive = k.toLowerCase().contains("key") || k.toLowerCase().contains("pem") || k.toLowerCase().contains("jwk");
                sb.append(k).append('=').append(sensitive ? "\u2022\u2022\u2022\u2022" : (v == null ? "" : (v.length() > 32 ? v.substring(0, 32) + "\u2026" : v)));
            });
            return sb.length() == 0 ? "(defaults)" : sb.toString();
        }
    }

    // ==================== step dialog ====================

    /** Per-type step editor. CardLayout swaps between dedicated forms. */
    private static final class StepDialog extends JDialog {
        Config.PipelineStep result;

        private final JComboBox<String> typeCombo     = heavyCombo(TYPES);
        private final JComboBox<String> inputEncCombo = heavyCombo(IO_FORMATS);
        private final JComboBox<String> outputEncCombo= heavyCombo(IO_FORMATS);
        private final Map<String, TypeForm> forms = new LinkedHashMap<>();
        private final JPanel formsHolder = new JPanel(new CardLayout());

        StepDialog(Window owner, Config.PipelineStep initial) {
            super(owner, initial == null ? "Add step" : "Edit step", ModalityType.APPLICATION_MODAL);
            setLayout(new BorderLayout(10, 10));
            ((JComponent) getContentPane()).setBorder(BorderFactory.createEmptyBorder(10, 12, 10, 12));

            // --- header: type selector ----
            JPanel header = new JPanel(new GridBagLayout());
            header.setBorder(BorderFactory.createCompoundBorder(
                    BorderFactory.createTitledBorder("Encryption method"),
                    BorderFactory.createEmptyBorder(4, 8, 6, 8)));
            GridBagConstraints g = new GridBagConstraints();
            g.insets = new Insets(4, 4, 4, 4);
            g.anchor = GridBagConstraints.WEST;
            g.gridx = 0; g.gridy = 0;
            header.add(new JLabel("Type:"), g);
            g.gridx = 1; g.weightx = 1.0; g.fill = GridBagConstraints.HORIZONTAL;
            header.add(typeCombo, g);
            add(header, BorderLayout.NORTH);

            // --- center: per-type forms ----
            forms.put("AES-256-CBC",    new AesCbcForm(256));
            forms.put("AES-128-CBC",    new AesCbcForm(128));
            forms.put("AES-256-GCM",    new AesGcmForm());
            forms.put("AES-256-ECB",    new AesEcbForm());
            forms.put("RSA-OAEP-HYBRID",new RsaOaepForm());
            forms.put("JWE",            new JweForm());
            forms.put("XOR",            new XorForm());
            forms.put("BASE64",         new Base64Form());
            for (Map.Entry<String, TypeForm> e : forms.entrySet()) {
                formsHolder.add(e.getValue().component(), e.getKey());
            }
            JScrollPane formsScroll = new JScrollPane(formsHolder);
            formsScroll.setBorder(BorderFactory.createTitledBorder("Parameters"));
            formsScroll.getVerticalScrollBar().setUnitIncrement(16);
            add(formsScroll, BorderLayout.CENTER);

            // --- footer: input/output encoding + buttons ----
            JPanel footer = new JPanel(new BorderLayout(8, 8));

            JPanel ioRow = new JPanel(new GridBagLayout());
            ioRow.setBorder(BorderFactory.createCompoundBorder(
                    BorderFactory.createTitledBorder("Data format (CyberChef-style)"),
                    BorderFactory.createEmptyBorder(4, 8, 6, 8)));
            GridBagConstraints gi = new GridBagConstraints();
            gi.insets = new Insets(4, 6, 4, 6);
            gi.anchor = GridBagConstraints.WEST;
            gi.gridy = 0;
            gi.gridx = 0; ioRow.add(new JLabel("Input:"),  gi);
            gi.gridx = 1; ioRow.add(inputEncCombo, gi);
            gi.gridx = 2; ioRow.add(Box.createHorizontalStrut(24), gi);
            gi.gridx = 3; ioRow.add(new JLabel("Output:"), gi);
            gi.gridx = 4; ioRow.add(outputEncCombo, gi);
            gi.gridx = 5; gi.weightx = 1.0; gi.fill = GridBagConstraints.HORIZONTAL;
            JLabel hint = new JLabel("raw = bytes as-is \u00B7 hex / base64 = text-encoded bytes");
            hint.setFont(hint.getFont().deriveFont(Font.ITALIC, hint.getFont().getSize2D() - 1f));
            hint.setForeground(new Color(100, 100, 100));
            ioRow.add(hint, gi);
            footer.add(ioRow, BorderLayout.CENTER);

            JPanel btns = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 4));
            JButton cancel = new JButton("Cancel");
            JButton ok     = new JButton("OK");
            cancel.setPreferredSize(new Dimension(110, 34));
            ok.setPreferredSize(new Dimension(110, 34));
            ok.setFont(ok.getFont().deriveFont(Font.BOLD));
            btns.add(cancel); btns.add(ok);
            footer.add(btns, BorderLayout.SOUTH);

            add(footer, BorderLayout.SOUTH);

            // --- wiring ----
            typeCombo.addActionListener(e -> {
                String t = (String) typeCombo.getSelectedItem();
                if (t != null) ((CardLayout) formsHolder.getLayout()).show(formsHolder, t);
            });
            cancel.addActionListener(e -> { result = null; dispose(); });
            ok.addActionListener(e -> {
                String type = (String) typeCombo.getSelectedItem();
                TypeForm form = forms.get(type);
                if (form == null) { dispose(); return; }
                Map<String, String> params;
                try {
                    params = form.collect();
                } catch (IllegalArgumentException ex) {
                    JOptionPane.showMessageDialog(this, ex.getMessage(), "Invalid parameters", JOptionPane.WARNING_MESSAGE);
                    return;
                }
                String inEnc  = (String) inputEncCombo.getSelectedItem();
                String outEnc = (String) outputEncCombo.getSelectedItem();
                if (inEnc  != null && !"raw".equals(inEnc))  params.put("input-encoding",  inEnc);
                if (outEnc != null && !"raw".equals(outEnc)) params.put("output-encoding", outEnc);
                Config.PipelineStep s = new Config.PipelineStep(type);
                s.enabled = initial != null ? initial.enabled : true;
                s.params  = params;
                result = s;
                dispose();
            });

            // --- preload ----
            if (initial != null) {
                typeCombo.setSelectedItem(initial.type);
                TypeForm form = forms.get(initial.type);
                if (form != null && initial.params != null) form.populate(initial.params);
                if (initial.params != null) {
                    inputEncCombo.setSelectedItem(initial.params.getOrDefault("input-encoding", "raw"));
                    outputEncCombo.setSelectedItem(initial.params.getOrDefault("output-encoding", "raw"));
                }
            }
            String t0 = (String) typeCombo.getSelectedItem();
            if (t0 != null) ((CardLayout) formsHolder.getLayout()).show(formsHolder, t0);

            setSize(760, 600);
            setLocationRelativeTo(owner);
            getRootPane().setDefaultButton(ok);
        }
    }

    // ==================== per-type forms ====================

    private interface TypeForm {
        JComponent component();
        /** Collect current field values as the params map. Throws IllegalArgumentException if required fields are missing. */
        Map<String, String> collect();
        void populate(Map<String, String> params);
    }

    /** Builder for rows in a GridBagLayout form. */
    private static final class FormBuilder {
        final JPanel panel = new JPanel(new GridBagLayout());
        int row = 0;
        FormBuilder() {
            panel.setBorder(BorderFactory.createEmptyBorder(8, 10, 8, 10));
        }
        private GridBagConstraints gc(int x, int y, int w, double wx, int fill) {
            GridBagConstraints g = new GridBagConstraints();
            g.gridx = x; g.gridy = y; g.gridwidth = w;
            g.insets = new Insets(4, 4, 4, 4);
            g.anchor = GridBagConstraints.WEST;
            g.weightx = wx; g.fill = fill;
            return g;
        }
        void addRow(String label, JComponent field) {
            panel.add(new JLabel(label), gc(0, row, 1, 0, GridBagConstraints.NONE));
            panel.add(field, gc(1, row, 2, 1.0, GridBagConstraints.HORIZONTAL));
            row++;
        }
        void addRow(String label, JComponent field, JComponent trailing) {
            panel.add(new JLabel(label), gc(0, row, 1, 0, GridBagConstraints.NONE));
            panel.add(field, gc(1, row, 1, 1.0, GridBagConstraints.HORIZONTAL));
            panel.add(trailing, gc(2, row, 1, 0, GridBagConstraints.NONE));
            row++;
        }
        void addWide(JComponent component) {
            panel.add(component, gc(0, row, 3, 1.0, GridBagConstraints.HORIZONTAL));
            row++;
        }
        void addNote(String text) {
            JLabel l = new JLabel(text);
            l.setFont(l.getFont().deriveFont(Font.ITALIC, l.getFont().getSize2D() - 1f));
            l.setForeground(new Color(110, 110, 110));
            GridBagConstraints g = gc(0, row, 3, 1.0, GridBagConstraints.HORIZONTAL);
            g.insets = new Insets(0, 4, 6, 4);
            panel.add(l, g);
            row++;
        }
        JComponent build() {
            // spacer bottom so fields don't stretch
            GridBagConstraints g = new GridBagConstraints();
            g.gridx = 0; g.gridy = row; g.gridwidth = 3; g.weighty = 1.0;
            g.fill = GridBagConstraints.VERTICAL;
            panel.add(Box.createVerticalGlue(), g);
            return panel;
        }
    }

    private static String s(Map<String, String> p, String k, String def) {
        String v = p.get(k);
        return v == null ? def : v;
    }

    // ---------- AES-CBC ----------
    private static final class AesCbcForm implements TypeForm {
        private final int keyBits;
        private final JTextField keyField = new JTextField();
        private final JComboBox<String> keyEnc = heavyCombo(ENCODINGS);
        private final JRadioButton ivRandom = new JRadioButton("random (prepended to ciphertext)");
        private final JRadioButton ivFixed  = new JRadioButton("fixed value");
        private final JTextField ivField = new JTextField();
        private final JComboBox<String> ivEnc = heavyCombo(ENCODINGS);
        private final JComponent comp;

        AesCbcForm(int keyBits) {
            this.keyBits = keyBits;
            ButtonGroup bg = new ButtonGroup(); bg.add(ivRandom); bg.add(ivFixed);
            ivRandom.setSelected(true);
            FormBuilder f = new FormBuilder();
            f.addRow("Key:", keyField, keyEnc);
            f.addNote("AES-" + keyBits + "-CBC requires a " + (keyBits / 8) + "-byte key.");
            JPanel ivRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
            ivRow.add(new JLabel("IV mode:")); ivRow.add(ivRandom); ivRow.add(ivFixed);
            f.addWide(ivRow);
            f.addRow("IV:", ivField, ivEnc);
            comp = f.build();

            Runnable sync = () -> {
                boolean fixed = ivFixed.isSelected();
                ivField.setEnabled(fixed); ivEnc.setEnabled(fixed);
            };
            ivRandom.addActionListener(e -> sync.run());
            ivFixed.addActionListener(e -> sync.run());
            sync.run();
        }

        @Override public JComponent component() { return comp; }

        @Override public Map<String, String> collect() {
            if (keyField.getText().isBlank()) throw new IllegalArgumentException("Key is required.");
            Map<String, String> p = new LinkedHashMap<>();
            p.put("key", keyField.getText().trim());
            p.put("key-encoding", (String) keyEnc.getSelectedItem());
            if (ivFixed.isSelected()) {
                if (ivField.getText().isBlank()) throw new IllegalArgumentException("IV is required in fixed mode.");
                p.put("iv-mode", "fixed");
                p.put("iv", ivField.getText().trim());
                p.put("iv-encoding", (String) ivEnc.getSelectedItem());
            } else {
                p.put("iv-mode", "random");
            }
            return p;
        }

        @Override public void populate(Map<String, String> p) {
            keyField.setText(s(p, "key", ""));
            keyEnc.setSelectedItem(s(p, "key-encoding", "hex"));
            String mode = s(p, "iv-mode", "fixed").toLowerCase();
            boolean rand = mode.equals("random") || mode.equals("random-prepended") || mode.equals("prepended");
            ivRandom.setSelected(rand); ivFixed.setSelected(!rand);
            ivField.setText(s(p, "iv", ""));
            ivEnc.setSelectedItem(s(p, "iv-encoding", "hex"));
            ivField.setEnabled(!rand); ivEnc.setEnabled(!rand);
        }
    }

    // ---------- AES-GCM ----------
    private static final class AesGcmForm implements TypeForm {
        private final JTextField keyField = new JTextField();
        private final JComboBox<String> keyEnc = heavyCombo(ENCODINGS);
        private final JRadioButton nonceRandom = new JRadioButton("random (12 bytes, prepended)");
        private final JRadioButton nonceFixed  = new JRadioButton("fixed value");
        private final JTextField nonceField = new JTextField();
        private final JComboBox<String> nonceEnc = heavyCombo(ENCODINGS);
        private final JTextField aadField = new JTextField();
        private final JComboBox<String> aadEnc = heavyCombo(ENCODINGS);
        private final JComponent comp;

        AesGcmForm() {
            ButtonGroup bg = new ButtonGroup(); bg.add(nonceRandom); bg.add(nonceFixed);
            nonceRandom.setSelected(true);
            FormBuilder f = new FormBuilder();
            f.addRow("Key:", keyField, keyEnc);
            f.addNote("AES-256-GCM requires a 32-byte key.");
            JPanel row = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
            row.add(new JLabel("Nonce mode:")); row.add(nonceRandom); row.add(nonceFixed);
            f.addWide(row);
            f.addRow("Nonce:", nonceField, nonceEnc);
            f.addRow("AAD (optional):", aadField, aadEnc);
            aadEnc.setSelectedItem("utf-8");
            comp = f.build();

            Runnable sync = () -> {
                boolean fixed = nonceFixed.isSelected();
                nonceField.setEnabled(fixed); nonceEnc.setEnabled(fixed);
            };
            nonceRandom.addActionListener(e -> sync.run());
            nonceFixed.addActionListener(e -> sync.run());
            sync.run();
        }

        @Override public JComponent component() { return comp; }

        @Override public Map<String, String> collect() {
            if (keyField.getText().isBlank()) throw new IllegalArgumentException("Key is required.");
            Map<String, String> p = new LinkedHashMap<>();
            p.put("key", keyField.getText().trim());
            p.put("key-encoding", (String) keyEnc.getSelectedItem());
            if (nonceFixed.isSelected()) {
                if (nonceField.getText().isBlank()) throw new IllegalArgumentException("Nonce is required in fixed mode.");
                p.put("nonce-mode", "fixed");
                p.put("nonce", nonceField.getText().trim());
                p.put("nonce-encoding", (String) nonceEnc.getSelectedItem());
            } else {
                p.put("nonce-mode", "random");
            }
            if (!aadField.getText().isBlank()) {
                p.put("aad", aadField.getText().trim());
                p.put("aad-encoding", (String) aadEnc.getSelectedItem());
            }
            return p;
        }

        @Override public void populate(Map<String, String> p) {
            keyField.setText(s(p, "key", ""));
            keyEnc.setSelectedItem(s(p, "key-encoding", "hex"));
            String mode = s(p, "nonce-mode", "random").toLowerCase();
            boolean fixed = mode.equals("fixed");
            nonceFixed.setSelected(fixed); nonceRandom.setSelected(!fixed);
            nonceField.setText(s(p, "nonce", ""));
            nonceEnc.setSelectedItem(s(p, "nonce-encoding", "hex"));
            aadField.setText(s(p, "aad", ""));
            aadEnc.setSelectedItem(s(p, "aad-encoding", "utf-8"));
            nonceField.setEnabled(fixed); nonceEnc.setEnabled(fixed);
        }
    }

    // ---------- AES-ECB ----------
    private static final class AesEcbForm implements TypeForm {
        private final JTextField keyField = new JTextField();
        private final JComboBox<String> keyEnc = heavyCombo(ENCODINGS);
        private final JComponent comp;

        AesEcbForm() {
            FormBuilder f = new FormBuilder();
            f.addRow("Key:", keyField, keyEnc);
            f.addNote("AES-ECB is deterministic and leaks repeated blocks. Use only when the target app forces it.");
            comp = f.build();
        }

        @Override public JComponent component() { return comp; }

        @Override public Map<String, String> collect() {
            if (keyField.getText().isBlank()) throw new IllegalArgumentException("Key is required.");
            Map<String, String> p = new LinkedHashMap<>();
            p.put("key", keyField.getText().trim());
            p.put("key-encoding", (String) keyEnc.getSelectedItem());
            return p;
        }

        @Override public void populate(Map<String, String> p) {
            keyField.setText(s(p, "key", ""));
            keyEnc.setSelectedItem(s(p, "key-encoding", "hex"));
        }
    }

    // ---------- XOR ----------
    private static final class XorForm implements TypeForm {
        private final JTextField keyField = new JTextField();
        private final JComboBox<String> keyEnc = heavyCombo(ENCODINGS);
        private final JRadioButton modeRepeat = new JRadioButton("repeat key across input");
        private final JRadioButton modeTruncate = new JRadioButton("truncate input to key length");
        private final JComponent comp;

        XorForm() {
            ButtonGroup bg = new ButtonGroup(); bg.add(modeRepeat); bg.add(modeTruncate);
            modeRepeat.setSelected(true);
            FormBuilder f = new FormBuilder();
            f.addRow("Key:", keyField, keyEnc);
            f.addWide(modeRepeat);
            f.addWide(modeTruncate);
            comp = f.build();
        }

        @Override public JComponent component() { return comp; }

        @Override public Map<String, String> collect() {
            if (keyField.getText().isBlank()) throw new IllegalArgumentException("Key is required.");
            Map<String, String> p = new LinkedHashMap<>();
            p.put("key", keyField.getText().trim());
            p.put("key-encoding", (String) keyEnc.getSelectedItem());
            p.put("repeat-mode", modeTruncate.isSelected() ? "truncate" : "repeat");
            return p;
        }

        @Override public void populate(Map<String, String> p) {
            keyField.setText(s(p, "key", ""));
            keyEnc.setSelectedItem(s(p, "key-encoding", "hex"));
            boolean trunc = "truncate".equalsIgnoreCase(s(p, "repeat-mode", "repeat"));
            modeTruncate.setSelected(trunc); modeRepeat.setSelected(!trunc);
        }
    }

    // ---------- BASE64 ----------
    private static final class Base64Form implements TypeForm {
        private final JComboBox<String> variant = heavyCombo("standard", "url-safe");
        private final JCheckBox padding = new JCheckBox("include '=' padding", true);
        private final JComponent comp;

        Base64Form() {
            FormBuilder f = new FormBuilder();
            f.addRow("Variant:", variant);
            f.addWide(padding);
            f.addNote("url-safe replaces '+' with '-' and '/' with '_'.");
            comp = f.build();
        }

        @Override public JComponent component() { return comp; }

        @Override public Map<String, String> collect() {
            Map<String, String> p = new LinkedHashMap<>();
            p.put("variant", (String) variant.getSelectedItem());
            p.put("padding", Boolean.toString(padding.isSelected()));
            return p;
        }

        @Override public void populate(Map<String, String> p) {
            String v = s(p, "variant", "standard").toLowerCase();
            variant.setSelectedItem(v.startsWith("url") ? "url-safe" : "standard");
            padding.setSelected(!"false".equalsIgnoreCase(s(p, "padding", "true")));
        }
    }

    // ---------- RSA-OAEP-HYBRID ----------
    private static final class RsaOaepForm implements TypeForm {
        private final JTextArea pubPem  = new JTextArea(5, 50);
        private final JTextArea privPem = new JTextArea(5, 50);
        private final JComboBox<String> oaepHash = heavyCombo("SHA-256", "SHA-1", "SHA-384", "SHA-512");
        private final JComboBox<String> aesBits  = heavyCombo("256", "192", "128");
        private final JComboBox<String> inner    = heavyCombo("aes-gcm", "aes-cbc");
        private final JComponent comp;

        RsaOaepForm() {
            pubPem.setLineWrap(false);  privPem.setLineWrap(false);
            pubPem.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
            privPem.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
            FormBuilder f = new FormBuilder();
            f.addRow("Public key (PEM):",  new JScrollPane(pubPem));
            f.addRow("Private key (PEM):", new JScrollPane(privPem));
            f.addRow("OAEP hash:", oaepHash);
            f.addRow("AES bits:",  aesBits);
            f.addRow("Inner cipher:", inner);
            f.addNote("Public key is needed to encrypt; private key to decrypt.");
            comp = f.build();
        }

        @Override public JComponent component() { return comp; }

        @Override public Map<String, String> collect() {
            Map<String, String> p = new LinkedHashMap<>();
            if (!pubPem.getText().isBlank())  p.put("public-key-pem",  pubPem.getText().trim());
            if (!privPem.getText().isBlank()) p.put("private-key-pem", privPem.getText().trim());
            if (p.isEmpty()) throw new IllegalArgumentException("Provide at least one of public-key-pem or private-key-pem.");
            p.put("oaep-hash", (String) oaepHash.getSelectedItem());
            p.put("aes-bits",  (String) aesBits.getSelectedItem());
            p.put("inner",     (String) inner.getSelectedItem());
            return p;
        }

        @Override public void populate(Map<String, String> p) {
            pubPem.setText(s(p, "public-key-pem", ""));
            privPem.setText(s(p, "private-key-pem", ""));
            oaepHash.setSelectedItem(s(p, "oaep-hash", "SHA-256"));
            aesBits.setSelectedItem(s(p, "aes-bits", "256"));
            inner.setSelectedItem(s(p, "inner", "aes-gcm"));
        }
    }

    // ---------- JWE ----------
    private static final class JweForm implements TypeForm {
        private final JComboBox<String> alg = heavyCombo("RSA-OAEP-256", "RSA-OAEP", "dir", "ECDH-ES", "ECDH-ES+A256KW");
        private final JComboBox<String> enc = heavyCombo("A256GCM", "A128GCM", "A256CBC-HS512", "A128CBC-HS256");
        private final JTextArea pubJwk  = new JTextArea(5, 50);
        private final JTextArea privJwk = new JTextArea(5, 50);
        private final JComponent comp;

        JweForm() {
            pubJwk.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
            privJwk.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
            FormBuilder f = new FormBuilder();
            f.addRow("alg:", alg);
            f.addRow("enc:", enc);
            f.addRow("JWK public:",  new JScrollPane(pubJwk));
            f.addRow("JWK private:", new JScrollPane(privJwk));
            f.addNote("For 'dir' use JWK public = JWK private = a symmetric JWK.");
            comp = f.build();
        }

        @Override public JComponent component() { return comp; }

        @Override public Map<String, String> collect() {
            Map<String, String> p = new LinkedHashMap<>();
            p.put("alg", (String) alg.getSelectedItem());
            p.put("enc", (String) enc.getSelectedItem());
            if (!pubJwk.getText().isBlank())  p.put("jwk-public",  pubJwk.getText().trim());
            if (!privJwk.getText().isBlank()) p.put("jwk-private", privJwk.getText().trim());
            if (!p.containsKey("jwk-public") && !p.containsKey("jwk-private"))
                throw new IllegalArgumentException("Provide at least one JWK (public to encrypt, private to decrypt).");
            return p;
        }

        @Override public void populate(Map<String, String> p) {
            alg.setSelectedItem(s(p, "alg", "RSA-OAEP-256"));
            enc.setSelectedItem(s(p, "enc", "A256GCM"));
            pubJwk.setText(s(p, "jwk-public", ""));
            privJwk.setText(s(p, "jwk-private", ""));
        }
    }
}
