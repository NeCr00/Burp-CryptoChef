package com.cryptomobile.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Map;

/**
 * AES-ECB with PKCS#7 padding. Included for compatibility with mobile apps
 * that genuinely use it — it is not safe, but ECB is depressingly common in
 * the wild.
 */
public final class AesEcbStep implements CipherStep {

    private final byte[] key;
    private final int keyBits;

    public AesEcbStep(byte[] key) throws CipherStepException {
        if (key.length != 16 && key.length != 24 && key.length != 32)
            throw new CipherStepException("AES-ECB: key must be 16, 24, or 32 bytes, got " + key.length);
        this.key = key.clone();
        this.keyBits = key.length * 8;
    }

    public static AesEcbStep fromParams(Map<String, String> params, int expectedBits) throws CipherStepException {
        byte[] k = KeyMaterialCodec.decode(params.getOrDefault("key-encoding", "auto"), params.get("key"));
        if (expectedBits > 0 && k.length * 8 != expectedBits)
            throw new CipherStepException("AES-" + expectedBits + "-ECB: expected " + (expectedBits / 8) + "-byte key, got " + k.length);
        return new AesEcbStep(k);
    }

    @Override public String name() { return "AES-" + keyBits + "-ECB"; }

    @Override
    public byte[] encrypt(byte[] input) throws CipherStepException {
        try {
            Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
            return c.doFinal(input);
        } catch (Exception e) {
            throw new CipherStepException(name() + ": encryption failed: " + e.getMessage(), e);
        }
    }

    @Override
    public byte[] decrypt(byte[] input) throws CipherStepException {
        try {
            Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"));
            return c.doFinal(input);
        } catch (javax.crypto.BadPaddingException bpe) {
            throw new CipherStepException(name() + ": bad padding (wrong key)", bpe);
        } catch (Exception e) {
            throw new CipherStepException(name() + ": decryption failed: " + e.getMessage(), e);
        }
    }
}
