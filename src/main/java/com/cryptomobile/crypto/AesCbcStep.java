package com.cryptomobile.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Map;

/**
 * AES-CBC with PKCS#7 padding. Supports 128/192/256-bit keys.
 *
 * <p><b>IV handling:</b> on encryption, either a fixed IV (param {@code iv})
 * or {@code iv-mode=random} (16 random bytes prepended to the ciphertext)
 * can be used. On decryption, if {@code iv-mode=prepended} the first 16
 * bytes are consumed as the IV; otherwise the fixed IV is used.
 */
public final class AesCbcStep implements CipherStep {

    public enum IvMode { FIXED, RANDOM_PREPENDED }

    private final byte[] key;
    private final byte[] fixedIv;
    private final IvMode ivMode;
    private final int keyBits;

    private static final SecureRandom RNG = new SecureRandom();

    public AesCbcStep(byte[] key, byte[] fixedIv, IvMode ivMode) throws CipherStepException {
        if (key.length != 16 && key.length != 24 && key.length != 32)
            throw new CipherStepException("AES-CBC: key must be 16, 24, or 32 bytes, got " + key.length);
        if (ivMode == IvMode.FIXED && (fixedIv == null || fixedIv.length != 16))
            throw new CipherStepException("AES-CBC: fixed IV must be 16 bytes, got " + (fixedIv == null ? 0 : fixedIv.length));
        this.key = key.clone();
        this.fixedIv = fixedIv == null ? null : fixedIv.clone();
        this.ivMode = ivMode;
        this.keyBits = key.length * 8;
    }

    public static AesCbcStep fromParams(Map<String, String> params, int expectedBits) throws CipherStepException {
        String keyEnc = params.getOrDefault("key-encoding", "auto");
        byte[] k = KeyMaterialCodec.decode(keyEnc, params.get("key"));
        if (expectedBits > 0 && k.length * 8 != expectedBits)
            throw new CipherStepException("AES-" + expectedBits + "-CBC: expected " + (expectedBits / 8) + "-byte key, got " + k.length);
        String ivModeRaw = params.getOrDefault("iv-mode", "fixed").toLowerCase();
        IvMode ivMode = switch (ivModeRaw) {
            case "random", "random-prepended", "prepended" -> IvMode.RANDOM_PREPENDED;
            default -> IvMode.FIXED;
        };
        byte[] iv = null;
        if (ivMode == IvMode.FIXED) {
            iv = KeyMaterialCodec.decode(params.getOrDefault("iv-encoding", "auto"), params.getOrDefault("iv", ""));
        }
        return new AesCbcStep(k, iv, ivMode);
    }

    @Override public String name() { return "AES-" + keyBits + "-CBC"; }

    @Override
    public byte[] encrypt(byte[] input) throws CipherStepException {
        try {
            byte[] iv = ivMode == IvMode.RANDOM_PREPENDED ? randomIv() : fixedIv;
            Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
            byte[] ct = c.doFinal(input);
            if (ivMode == IvMode.RANDOM_PREPENDED) {
                byte[] out = new byte[iv.length + ct.length];
                System.arraycopy(iv, 0, out, 0, iv.length);
                System.arraycopy(ct, 0, out, iv.length, ct.length);
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
            byte[] iv;
            byte[] body;
            if (ivMode == IvMode.RANDOM_PREPENDED) {
                if (input.length < 16)
                    throw new CipherStepException(name() + ": ciphertext too short to contain IV");
                iv   = Arrays.copyOfRange(input, 0, 16);
                body = Arrays.copyOfRange(input, 16, input.length);
            } else {
                iv   = fixedIv;
                body = input;
            }
            Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
            return c.doFinal(body);
        } catch (javax.crypto.BadPaddingException bpe) {
            throw new CipherStepException(name() + ": bad padding (wrong key or wrong IV)", bpe);
        } catch (Exception e) {
            throw new CipherStepException(name() + ": decryption failed: " + e.getMessage(), e);
        }
    }

    private static byte[] randomIv() {
        byte[] iv = new byte[16];
        RNG.nextBytes(iv);
        return iv;
    }
}
