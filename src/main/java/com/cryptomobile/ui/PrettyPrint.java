package com.cryptomobile.ui;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

/** Best-effort JSON/XML pretty-printer used by the Decrypted editor tabs. */
public final class PrettyPrint {

    private static final Gson PRETTY = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();

    private PrettyPrint() {}

    /** Returns the pretty form if the bytes parse as JSON or XML; otherwise
     *  returns the original bytes unchanged. Never throws. */
    public static byte[] maybePretty(byte[] bytes) {
        if (bytes == null || bytes.length == 0) return bytes == null ? new byte[0] : bytes;
        String s = new String(bytes, StandardCharsets.UTF_8).trim();
        if (s.isEmpty()) return bytes;

        // JSON
        char first = s.charAt(0);
        if (first == '{' || first == '[') {
            try {
                JsonElement el = com.google.gson.JsonParser.parseString(s);
                return PRETTY.toJson(el).getBytes(StandardCharsets.UTF_8);
            } catch (Exception ignored) { /* fall through */ }
        }
        // XML
        if (first == '<') {
            try {
                javax.xml.parsers.DocumentBuilderFactory dbf = javax.xml.parsers.DocumentBuilderFactory.newInstance();
                dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
                org.w3c.dom.Document doc = dbf.newDocumentBuilder().parse(new ByteArrayInputStream(bytes));
                javax.xml.transform.TransformerFactory tf = javax.xml.transform.TransformerFactory.newInstance();
                javax.xml.transform.Transformer t = tf.newTransformer();
                t.setOutputProperty(javax.xml.transform.OutputKeys.INDENT, "yes");
                t.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                t.transform(new javax.xml.transform.dom.DOMSource(doc), new javax.xml.transform.stream.StreamResult(bos));
                return bos.toByteArray();
            } catch (Exception ignored) { /* fall through */ }
        }
        return bytes;
    }
}
