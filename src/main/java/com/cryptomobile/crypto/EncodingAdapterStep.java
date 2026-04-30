package com.cryptomobile.crypto;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HexFormat;

/**
 * CyberChef-style wrapper: transforms the bytes going in and coming out of
 * another {@link CipherStep} using a textual encoding (hex / base64 / raw).
 *
 * <p>On {@code encrypt}: {@code decode(input, inputEncoding) → inner.encrypt → encode(output, outputEncoding)}.
 * <p>On {@code decrypt} (the inverse): {@code decode(input, outputEncoding) → inner.decrypt → encode(output, inputEncoding)}.
 * This makes the adapter itself invertible, matching the pipeline's run-then-reverse semantics.
 */
final class EncodingAdapterStep implements CipherStep {

    private final CipherStep inner;
    private final String inputEncoding;
    private final String outputEncoding;

    EncodingAdapterStep(CipherStep inner, String inputEncoding, String outputEncoding) {
        this.inner = inner;
        this.inputEncoding  = norm(inputEncoding);
        this.outputEncoding = norm(outputEncoding);
    }

    private static String norm(String s) {
        if (s == null) return "raw";
        String t = s.trim().toLowerCase();
        return t.isEmpty() ? "raw" : t;
    }

    @Override public String name() { return inner.name(); }

    @Override public byte[] encrypt(byte[] input) throws CipherStepException {
        byte[] decoded = decode(input, inputEncoding);
        byte[] out = inner.encrypt(decoded);
        return encode(out, outputEncoding);
    }

    @Override public byte[] decrypt(byte[] input) throws CipherStepException {
        byte[] decoded = decode(input, outputEncoding);
        byte[] out = inner.decrypt(decoded);
        return encode(out, inputEncoding);
    }

    private static byte[] decode(byte[] input, String enc) throws CipherStepException {
        if (enc.equals("raw")) return input;
        String s = new String(input, StandardCharsets.UTF_8).trim();
        try {
            return switch (enc) {
                case "hex"    -> HexFormat.of().parseHex(s.replaceAll("\\s+", ""));
                case "base64" -> KeyMaterialCodec.decodeBase64Tolerant(s);
                default       -> throw new CipherStepException("unknown encoding: " + enc);
            };
        } catch (IllegalArgumentException e) {
            throw new CipherStepException("could not decode input as " + enc + ": " + e.getMessage(), e);
        }
    }

    private static byte[] encode(byte[] input, String enc) {
        return switch (enc) {
            case "hex"    -> HexFormat.of().formatHex(input).getBytes(StandardCharsets.UTF_8);
            case "base64" -> Base64.getEncoder().encodeToString(input).getBytes(StandardCharsets.UTF_8);
            default       -> input;
        };
    }
}
