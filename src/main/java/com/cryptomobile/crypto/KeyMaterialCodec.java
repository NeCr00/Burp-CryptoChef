package com.cryptomobile.crypto;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HexFormat;

/**
 * Tolerant decoder for key material entered by pen-testers.
 *
 * <p>The UI allows keys to be pasted in hex, base64, or raw UTF-8. The crypto
 * layer is strict — wrong key length means wrong key. This class gives us a
 * single, well-tested parser so each step doesn't reinvent the wheel.
 */
public final class KeyMaterialCodec {

    private KeyMaterialCodec() {}

    /** Decode by explicit encoding ({@code "hex" | "base64" | "utf-8"}). */
    public static byte[] decode(String encoding, String input) throws CipherStepException {
        if (input == null) throw new CipherStepException("key material is null");
        String s = input.trim();
        if (s.isEmpty()) throw new CipherStepException("key material is empty");
        try {
            return switch (encoding == null ? "auto" : encoding.toLowerCase()) {
                case "hex"    -> HexFormat.of().parseHex(stripHex(s));
                case "base64" -> decodeBase64Tolerant(s);
                case "utf-8", "utf8", "ascii" -> s.getBytes(StandardCharsets.UTF_8);
                case "auto"   -> autoDetect(s);
                default       -> throw new CipherStepException("unknown encoding: " + encoding);
            };
        } catch (IllegalArgumentException e) {
            throw new CipherStepException("could not decode key material as " + encoding + ": " + e.getMessage(), e);
        }
    }

    /** Best-effort format guess — hex > base64 > utf-8. */
    public static byte[] autoDetect(String s) {
        String t = s.trim();
        String h = stripHex(t);
        if (h.length() % 2 == 0 && h.chars().allMatch(c -> (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
            return HexFormat.of().parseHex(h);
        }
        try {
            return decodeBase64Tolerant(t);
        } catch (IllegalArgumentException ignored) { /* fall through */ }
        return t.getBytes(StandardCharsets.UTF_8);
    }

    /** Accept both standard and URL-safe base64, with or without padding. */
    public static byte[] decodeBase64Tolerant(String s) {
        String t = s.replaceAll("\\s+", "");
        try {
            return Base64.getDecoder().decode(t);
        } catch (IllegalArgumentException ignored) { /* try next */ }
        try {
            return Base64.getUrlDecoder().decode(t);
        } catch (IllegalArgumentException ignored) { /* try next */ }
        // Add padding and retry
        int pad = (4 - (t.length() % 4)) % 4;
        String padded = t + "=".repeat(pad);
        try {
            return Base64.getDecoder().decode(padded);
        } catch (IllegalArgumentException ignored) { /* try url */ }
        return Base64.getUrlDecoder().decode(padded);
    }

    private static String stripHex(String s) {
        return s.replace("0x", "").replace("0X", "").replaceAll("[\\s:_-]+", "");
    }

    /** Parse a PEM-encoded PKCS#8 / SEC1 / X.509 key body (--BEGIN/END strippable). */
    public static byte[] stripPem(String pem) {
        String body = pem.replaceAll("-----BEGIN [A-Z0-9 ]+-----", "")
                         .replaceAll("-----END [A-Z0-9 ]+-----", "")
                         .replaceAll("\\s+", "");
        return Base64.getDecoder().decode(body);
    }

    public static PublicKey parsePublicKey(String pem, String algo) throws CipherStepException {
        try {
            byte[] der = stripPem(pem);
            return KeyFactory.getInstance(algo).generatePublic(new X509EncodedKeySpec(der));
        } catch (Exception e) {
            throw new CipherStepException("invalid " + algo + " public key PEM: " + e.getMessage(), e);
        }
    }

    public static PrivateKey parsePrivateKey(String pem, String algo) throws CipherStepException {
        try {
            byte[] der = stripPem(pem);
            return KeyFactory.getInstance(algo).generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (Exception e) {
            throw new CipherStepException("invalid " + algo + " private key PEM: " + e.getMessage(), e);
        }
    }
}
