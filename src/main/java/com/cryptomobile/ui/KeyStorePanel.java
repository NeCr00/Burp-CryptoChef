package com.cryptomobile.ui;

import burp.api.montoya.MontoyaApi;
import com.cryptomobile.config.Config;
import com.cryptomobile.config.ConfigStore;
import com.google.gson.reflect.TypeToken;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.io.IOException;
import java.lang.reflect.Type;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/** F3.2 — Key Material Store UI. */
public final class KeyStorePanel extends JPanel {

    private final MontoyaApi api;
    private final ConfigStore store;
    private final KeyTableModel model = new KeyTableModel();
    private final JTable table = new JTable(model);

    public KeyStorePanel(MontoyaApi api, ConfigStore store) {
        super(new BorderLayout(8, 8));
        this.api = api;
        this.store = store;

        add(new JScrollPane(table), BorderLayout.CENTER);
        JPanel btns = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton add = new JButton("Add key");
        JButton edit = new JButton("Edit");
        JButton del = new JButton("Remove");
        JButton importBtn = new JButton("Import JSON");
        JButton exportBtn = new JButton("Export JSON");
        btns.add(add); btns.add(edit); btns.add(del); btns.add(importBtn); btns.add(exportBtn);
        add(btns, BorderLayout.SOUTH);

        JLabel warn = new JLabel("⚠  Keys are stored in plaintext in the Burp project file. "
                + "Only import/export this file on trusted systems.");
        warn.setForeground(new Color(0x8B0000));
        warn.setBorder(BorderFactory.createEmptyBorder(4, 8, 4, 8));
        add(warn, BorderLayout.NORTH);

        add.addActionListener(e -> editKey(null));
        edit.addActionListener(e -> {
            int r = table.getSelectedRow();
            if (r < 0) { JOptionPane.showMessageDialog(this, "Select a key row first."); return; }
            List<Config.NamedKey> keys = store.get().keys;
            if (r >= keys.size()) return;
            editKey(keys.get(r));
        });
        del.addActionListener(e -> {
            int r = table.getSelectedRow();
            if (r < 0) { JOptionPane.showMessageDialog(this, "Select a key row first."); return; }
            List<Config.NamedKey> keys = store.get().keys;
            if (r >= keys.size()) return;
            String name = keys.get(r).name;
            if (JOptionPane.showConfirmDialog(this, "Remove key '" + name + "'?", "Confirm",
                    JOptionPane.OK_CANCEL_OPTION) != JOptionPane.OK_OPTION) return;
            store.update(c -> c.keys.removeIf(k -> name.equals(k.name)));
            refresh();
        });
        importBtn.addActionListener(e -> importJson());
        exportBtn.addActionListener(e -> exportJson());

        // Double-click a row to edit.
        table.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override public void mouseClicked(java.awt.event.MouseEvent ev) {
                if (ev.getClickCount() == 2) {
                    int r = table.getSelectedRow();
                    List<Config.NamedKey> keys = store.get().keys;
                    if (r >= 0 && r < keys.size()) editKey(keys.get(r));
                }
            }
        });

        store.addListener(c -> SwingUtilities.invokeLater(this::refresh));
        refresh();
    }

    public void refresh() { model.setKeys(store.get().keys); }

    private void editKey(Config.NamedKey existing) {
        JTextField name = new JTextField(existing == null ? "" : existing.name, 20);
        JComboBox<String> kind = new JComboBox<>(new String[]{"raw", "pem-public", "pem-private", "jwk"});
        kind.setLightWeightPopupEnabled(false);
        kind.setSelectedItem(existing == null ? "raw" : existing.kind);
        JComboBox<String> enc = new JComboBox<>(new String[]{"hex", "base64", "utf-8", "pem", "jwk-json"});
        enc.setLightWeightPopupEnabled(false);
        enc.setSelectedItem(existing == null ? "hex" : existing.encoding);
        JTextArea material = new JTextArea(existing == null ? "" : existing.material, 10, 50);
        material.setLineWrap(true);
        JTextField notes = new JTextField(existing == null ? "" : existing.notes, 40);

        JPanel form = new JPanel(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(4, 4, 4, 4);
        c.fill = GridBagConstraints.HORIZONTAL;
        c.gridx = 0; c.gridy = 0; form.add(new JLabel("Name:"), c);
        c.gridx = 1; form.add(name, c);
        c.gridx = 0; c.gridy = 1; form.add(new JLabel("Kind:"), c);
        c.gridx = 1; form.add(kind, c);
        c.gridx = 0; c.gridy = 2; form.add(new JLabel("Encoding:"), c);
        c.gridx = 1; form.add(enc, c);
        c.gridx = 0; c.gridy = 3; form.add(new JLabel("Material:"), c);
        c.gridx = 1; c.weightx = 1; c.weighty = 1; c.fill = GridBagConstraints.BOTH;
        form.add(new JScrollPane(material), c);
        c.gridx = 0; c.gridy = 4; c.weightx = 0; c.weighty = 0; c.fill = GridBagConstraints.HORIZONTAL;
        form.add(new JLabel("Notes:"), c);
        c.gridx = 1; form.add(notes, c);

        int r = JOptionPane.showConfirmDialog(this, form, existing == null ? "New key" : "Edit key",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (r != JOptionPane.OK_OPTION) return;
        String nm = name.getText().trim();
        if (nm.isEmpty()) { JOptionPane.showMessageDialog(this, "Name is required."); return; }
        store.update(cfg -> {
            if (existing != null) cfg.keys.removeIf(k -> existing.name.equals(k.name));
            cfg.keys.removeIf(k -> nm.equals(k.name));
            Config.NamedKey nk = new Config.NamedKey(nm,
                    (String) kind.getSelectedItem(),
                    (String) enc.getSelectedItem(),
                    material.getText());
            nk.notes = notes.getText();
            cfg.keys.add(nk);
        });
        refresh();
    }

    private void importJson() {
        JFileChooser fc = new JFileChooser();
        if (fc.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) return;
        try {
            String text = Files.readString(fc.getSelectedFile().toPath());
            Type listType = new TypeToken<List<Config.NamedKey>>(){}.getType();
            List<Config.NamedKey> imported = store.gson().fromJson(text, listType);
            if (imported == null) return;
            store.update(cfg -> {
                for (Config.NamedKey nk : imported) {
                    cfg.keys.removeIf(k -> k.name.equals(nk.name));
                    cfg.keys.add(nk);
                }
            });
            refresh();
            JOptionPane.showMessageDialog(this, "Imported " + imported.size() + " keys.");
        } catch (IOException e) {
            JOptionPane.showMessageDialog(this, "Import failed: " + e.getMessage());
        }
    }

    private void exportJson() {
        JFileChooser fc = new JFileChooser();
        if (fc.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return;
        try {
            String json = store.gson().toJson(store.get().keys);
            Files.writeString(fc.getSelectedFile().toPath(), json);
        } catch (IOException e) {
            JOptionPane.showMessageDialog(this, "Export failed: " + e.getMessage());
        }
    }

    private static class KeyTableModel extends AbstractTableModel {
        private List<Config.NamedKey> keys = java.util.Collections.emptyList();
        void setKeys(List<Config.NamedKey> k) { keys = k; fireTableDataChanged(); }
        @Override public int getRowCount()    { return keys.size(); }
        @Override public int getColumnCount() { return 4; }
        @Override public String getColumnName(int c) {
            return switch (c) { case 0 -> "Name"; case 1 -> "Kind"; case 2 -> "Encoding"; default -> "Notes"; };
        }
        @Override public Object getValueAt(int r, int c) {
            Config.NamedKey k = keys.get(r);
            return switch (c) { case 0 -> k.name; case 1 -> k.kind; case 2 -> k.encoding; default -> k.notes; };
        }
        @Override public boolean isCellEditable(int r, int c) { return false; }
    }
}
