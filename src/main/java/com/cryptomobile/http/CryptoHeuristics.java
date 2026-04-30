package com.cryptomobile.http;

import com.google.gson.JsonParser;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;

/**
 * Content sniffers used to decide whether a given chunk of bytes is already
 * in a recognisable plaintext envelope (JSON, XML/SOAP, URL-encoded form,
 * plain human-readable text) — in which case we skip decryption — or looks
 * like an opaque ciphertext-ish blob (base64, JWT/JWE compact serialisation,
 * mostly-binary) — in which case we skip re-encryption.
 *
 * <p>Conservative by construction: when the sniffers are unsure, they return
 * {@code false} from {@link #looksLikePlaintext(byte[])} so the configured
 * pipeline still gets a chance to run. A user who has scoped the extension to
 * a host/URL has implicitly opted in; heuristics exist to catch endpoints
 * that deviate from the scoped norm (e.g. an error response that leaks JSON
 * instead of ciphertext).
 */
public final class CryptoHeuristics {

    private static final Pattern URL_FORM = Pattern.compile(
            "^[A-Za-z0-9._~%+\\-]+=[A-Za-z0-9._~%+\\-]*(&[A-Za-z0-9._~%+\\-]+=[A-Za-z0-9._~%+\\-]*)+$");

    private static final Pattern BASE64URL_PART = Pattern.compile("^[A-Za-z0-9_\\-]+$");
    private static final Pattern BASE64_PART    = Pattern.compile("^[A-Za-z0-9+/_=\\-]+$");

    private static final int MAX_STRUCTURED_PARSE_BYTES = 2 * 1024 * 1024; // 2 MiB cap

    private CryptoHeuristics() {}

    /**
     * Returns {@code true} if {@code bytes} looks like a recognisable plaintext
     * envelope — i.e. the extension should NOT attempt to decrypt it and should
     * pass it through untouched. Empty input counts as plaintext.
     */
    public static boolean looksLikePlaintext(byte[] bytes) {
        if (bytes == null || bytes.length == 0) return true;

        // Reject up-front anything that isn't valid UTF-8: structured-text
        // sniffers (JSON / XML / form-url) all assume the bytes decode cleanly,
        // and a binary blob that happens to start with '{' or '<' was being
        // probed by the parsers needlessly. Saves CPU and tightens the
        // ciphertext-vs-plaintext decision on raw binary cipher output.
        if (!isValidUtf8(bytes)) return false;

        String s = utf8(bytes).trim();
        if (s.isEmpty()) return true;

        if (looksLikeJson(s)) return true;
        if (looksLikeXml(s, bytes))  return true;
        if (looksLikeUrlForm(s)) return true;

        // JWS/JWE compact serialisation — opaque, treat as ciphertext-ish.
        if (looksLikeDottedBase64Envelope(s)) return false;

        // Single base64/base64url chunk with no structural markers — opaque.
        if (looksLikeBase64Blob(s)) return false;

        // Fallback: mostly-printable text with whitespace — e.g. HTML, CSV,
        // free-form plaintext. Binary / high-entropy bytes fall through to false.
        return looksLikeReadableText(bytes);
    }

    /** Strict UTF-8 validity check (the {@link String} constructor would
     *  otherwise silently substitute U+FFFD for malformed sequences and let
     *  binary data masquerade as text). */
    private static boolean isValidUtf8(byte[] b) {
        try {
            StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                    .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
                    .decode(java.nio.ByteBuffer.wrap(b));
            return true;
        } catch (java.nio.charset.CharacterCodingException e) {
            return false;
        }
    }

    /** Symmetric to {@link #looksLikePlaintext} — handy at call sites that want
     *  to skip re-encryption when the body already looks opaque/ciphertext-ish. */
    public static boolean looksLikeCiphertext(byte[] bytes) {
        if (bytes == null || bytes.length == 0) return false;
        return !looksLikePlaintext(bytes);
    }

    // ======================= sniffers =======================

    private static boolean looksLikeJson(String s) {
        if (s.length() > MAX_STRUCTURED_PARSE_BYTES) return false;
        if (s.isEmpty()) return false;
        char c0 = s.charAt(0);
        if (c0 != '{' && c0 != '[') return false;
        try {
            JsonParser.parseString(s);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean looksLikeXml(String s, byte[] bytes) {
        if (!s.startsWith("<")) return false;
        if (s.indexOf('>') < 0) return false;
        if (bytes.length > MAX_STRUCTURED_PARSE_BYTES) {
            // Don't pay the parser cost on huge bodies — accept the loose match.
            return s.startsWith("<?xml") || s.startsWith("<!DOCTYPE")
                    || s.regionMatches(true, 0, "<html", 0, 5)
                    || s.regionMatches(true, 0, "<soap", 0, 5);
        }
        try {
            javax.xml.parsers.DocumentBuilderFactory dbf = javax.xml.parsers.DocumentBuilderFactory.newInstance();
            // XXE / billion-laughs hardening — our only goal is "is this XML?",
            // we don't need entities, DTDs, or external resources to answer
            // that. Disabling them avoids parser-driven network access, file
            // reads, and exponential entity expansion on hostile inputs.
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            dbf.setXIncludeAware(false);
            dbf.setExpandEntityReferences(false);
            dbf.newDocumentBuilder().parse(new ByteArrayInputStream(bytes));
            return true;
        } catch (Exception ignored) {
            // Fallback loose match — covers HTML & DOCTYPE-gated XML.
            return s.startsWith("<?xml") || s.startsWith("<!DOCTYPE")
                    || s.regionMatches(true, 0, "<html", 0, 5);
        }
    }

    private static boolean looksLikeUrlForm(String s) {
        if (s.isEmpty() || s.length() > 16_384) return false;
        if (!s.contains("=") || s.indexOf('\n') >= 0) return false;
        return URL_FORM.matcher(s).matches();
    }

    /** Matches JWS (3 parts) and JWE (5 parts) compact serialisation — opaque. */
    private static boolean looksLikeDottedBase64Envelope(String s) {
        if (s.indexOf('.') < 0) return false;
        String[] parts = s.split("\\.", -1);
        if (parts.length != 3 && parts.length != 5) return false;
        for (int i = 0; i < parts.length; i++) {
            String p = parts[i];
            // JWE permits empty "aad" / "iv" slots in pathological cases; tolerate.
            if (p.isEmpty()) continue;
            if (!BASE64URL_PART.matcher(p).matches()) return false;
        }
        return true;
    }

    private static boolean looksLikeBase64Blob(String s) {
        int n = s.length();
        if (n < 16) return false;
        if (!BASE64_PART.matcher(s).matches()) return false;
        // A very short base64 string like "A1B2C3D4E5F6G7H8" has no way to be
        // distinguished from random identifiers; the length gate handles that.
        return true;
    }

    private static boolean looksLikeReadableText(byte[] bytes) {
        int printable = 0;
        int whitespace = 0;
        int total = bytes.length;
        for (byte b : bytes) {
            int c = b & 0xFF;
            if (c == ' ' || c == '\n' || c == '\r' || c == '\t') { printable++; whitespace++; }
            else if (c >= 0x20 && c < 0x7F) printable++;
            else if (c >= 0xC2) printable++; // UTF-8 multibyte start — accept
        }
        if (total == 0) return true;
        long ratio = printable * 100L / total;
        return whitespace > 0 && ratio >= 90;
    }

    private static String utf8(byte[] b) {
        return new String(b, StandardCharsets.UTF_8);
    }
}
