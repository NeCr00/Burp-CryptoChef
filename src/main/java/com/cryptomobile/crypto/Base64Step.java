package com.cryptomobile.crypto;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

/**
 * Base64 as a pipeline layer. On "encrypt" we base64-encode, on "decrypt"
 * we decode. Standard or URL-safe, optional padding.
 */
public final class Base64Step implements CipherStep {

    public enum Variant { STANDARD, URL_SAFE }

    private final Variant variant;
    private final boolean padding;

    public Base64Step(Variant variant, boolean padding) {
        this.variant = variant;
        this.padding = padding;
    }

    public static Base64Step fromParams(Map<String, String> params) {
        Variant v = "url".equalsIgnoreCase(params.getOrDefault("variant", "standard"))
                || "url-safe".equalsIgnoreCase(params.getOrDefault("variant", "standard"))
                ? Variant.URL_SAFE : Variant.STANDARD;
        boolean p = !"false".equalsIgnoreCase(params.getOrDefault("padding", "true"));
        return new Base64Step(v, p);
    }

    @Override public String name() { return "Base64" + (variant == Variant.URL_SAFE ? "-url" : ""); }

    @Override
    public byte[] encrypt(byte[] input) {
        Base64.Encoder enc = variant == Variant.URL_SAFE ? Base64.getUrlEncoder() : Base64.getEncoder();
        if (!padding) enc = enc.withoutPadding();
        return enc.encode(input);
    }

    @Override
    public byte[] decrypt(byte[] input) throws CipherStepException {
        try {
            // Be tolerant: strip whitespace, accept missing padding.
            String s = new String(input, StandardCharsets.US_ASCII).replaceAll("\\s+", "");
            return KeyMaterialCodec.decodeBase64Tolerant(s);
        } catch (IllegalArgumentException e) {
            throw new CipherStepException("Base64: not valid base64 (" + e.getMessage() + ")", e);
        }
    }
}
