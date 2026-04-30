package com.cryptomobile.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Map;

/**
 * AES-GCM with 128-bit authentication tag.
 *
 * <p>Layout on the wire when {@code nonce-mode=prepended}:
 * {@code [12-byte nonce][ciphertext][16-byte tag]}.
 *
 * <p>The GCM tag is appended to the ciphertext by the JDK provider by
 * default — we do not split/assemble it manually.
 */
public final class AesGcmStep implements CipherStep {

    public enum NonceMode { FIXED, RANDOM_PREPENDED }

    private static final SecureRandom RNG = new SecureRandom();
    private static final int TAG_BITS = 128;
    private static final int NONCE_LEN = 12;

    private final byte[] key;
    private final byte[] fixedNonce;
    private final byte[] aad;
    private final NonceMode nonceMode;
    private final int keyBits;

    public AesGcmStep(byte[] key, byte[] fixedNonce, byte[] aad, NonceMode nonceMode) throws CipherStepException {
        if (key.length != 16 && key.length != 24 && key.length != 32)
            throw new CipherStepException("AES-GCM: key must be 16, 24, or 32 bytes, got " + key.length);
        if (nonceMode == NonceMode.FIXED && (fixedNonce == null || fixedNonce.length != NONCE_LEN))
            throw new CipherStepException("AES-GCM: fixed nonce must be 12 bytes, got " + (fixedNonce == null ? 0 : fixedNonce.length));
        this.key = key.clone();
        this.fixedNonce = fixedNonce == null ? null : fixedNonce.clone();
        this.aad = aad == null ? null : aad.clone();
        this.nonceMode = nonceMode;
        this.keyBits = key.length * 8;
    }

    public static AesGcmStep fromParams(Map<String, String> params, int expectedBits) throws CipherStepException {
        byte[] k = KeyMaterialCodec.decode(params.getOrDefault("key-encoding", "auto"), params.get("key"));
        if (expectedBits > 0 && k.length * 8 != expectedBits)
            throw new CipherStepException("AES-" + expectedBits + "-GCM: expected " + (expectedBits / 8) + "-byte key, got " + k.length);
        NonceMode mode = "fixed".equalsIgnoreCase(params.getOrDefault("nonce-mode", "random"))
                ? NonceMode.FIXED : NonceMode.RANDOM_PREPENDED;
        byte[] nonce = null;
        if (mode == NonceMode.FIXED) {
            nonce = KeyMaterialCodec.decode(params.getOrDefault("nonce-encoding", "auto"), params.getOrDefault("nonce", ""));
        }
        byte[] aad = null;
        String aadStr = params.get("aad");
        if (aadStr != null && !aadStr.isEmpty())
            aad = KeyMaterialCodec.decode(params.getOrDefault("aad-encoding", "utf-8"), aadStr);
        return new AesGcmStep(k, nonce, aad, mode);
    }

    @Override public String name() { return "AES-" + keyBits + "-GCM"; }

    @Override
    public byte[] encrypt(byte[] input) throws CipherStepException {
        try {
            byte[] nonce = nonceMode == NonceMode.RANDOM_PREPENDED ? randomNonce() : fixedNonce;
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_BITS, nonce));
            if (aad != null) c.updateAAD(aad);
            byte[] ct = c.doFinal(input);
            if (nonceMode == NonceMode.RANDOM_PREPENDED) {
                byte[] out = new byte[nonce.length + ct.length];
                System.arraycopy(nonce, 0, out, 0, nonce.length);
                System.arraycopy(ct, 0, out, nonce.length, ct.length);
                return out;
            }
            return ct;
        } catch (Exception e) {
            throw new CipherStepException(name() + ": encryption failed: " + e.getMessage(), e);
        }
    }

    @Override
    public byte[] decrypt(byte[] input) throws CipherStepException {
        try {
            byte[] nonce;
            byte[] body;
            if (nonceMode == NonceMode.RANDOM_PREPENDED) {
                if (input.length < NONCE_LEN + TAG_BITS / 8)
                    throw new CipherStepException(name() + ": ciphertext too short");
                nonce = Arrays.copyOfRange(input, 0, NONCE_LEN);
                body  = Arrays.copyOfRange(input, NONCE_LEN, input.length);
            } else {
                nonce = fixedNonce;
                body  = input;
            }
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_BITS, nonce));
            if (aad != null) c.updateAAD(aad);
            return c.doFinal(body);
        } catch (javax.crypto.AEADBadTagException tag) {
            throw new CipherStepException(name() + ": authentication tag mismatch (wrong key, nonce, or AAD)", tag);
        } catch (Exception e) {
            throw new CipherStepException(name() + ": decryption failed: " + e.getMessage(), e);
        }
    }

    private static byte[] randomNonce() {
        byte[] n = new byte[NONCE_LEN];
        RNG.nextBytes(n);
        return n;
    }
}
