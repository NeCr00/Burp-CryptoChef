package com.cryptomobile.crypto;

import java.util.Map;

/**
 * Static-key XOR. Symmetric — encrypt and decrypt are the same op.
 *
 * <p>Two key-repeat modes are supported:
 * <ul>
 *   <li>{@code repeat} — key cycles over the plaintext (the usual case).</li>
 *   <li>{@code truncate} — if key is shorter than plaintext, remaining
 *       bytes pass through unchanged (occasionally seen in legacy apps).</li>
 * </ul>
 */
public final class XorStep implements CipherStep {

    public enum RepeatMode { REPEAT, TRUNCATE }

    private final byte[] key;
    private final RepeatMode mode;

    public XorStep(byte[] key, RepeatMode mode) throws CipherStepException {
        if (key == null || key.length == 0)
            throw new CipherStepException("XOR: key is empty");
        this.key = key.clone();
        this.mode = mode;
    }

    public static XorStep fromParams(Map<String, String> params) throws CipherStepException {
        byte[] k = KeyMaterialCodec.decode(params.getOrDefault("key-encoding", "auto"), params.get("key"));
        RepeatMode m = "truncate".equalsIgnoreCase(params.getOrDefault("repeat-mode", "repeat"))
                ? RepeatMode.TRUNCATE : RepeatMode.REPEAT;
        return new XorStep(k, m);
    }

    @Override public String name() { return "XOR"; }

    @Override
    public byte[] encrypt(byte[] input) {
        byte[] out = new byte[input.length];
        for (int i = 0; i < input.length; i++) {
            if (mode == RepeatMode.TRUNCATE && i >= key.length) {
                out[i] = input[i];
            } else {
                out[i] = (byte) (input[i] ^ key[i % key.length]);
            }
        }
        return out;
    }

    @Override
    public byte[] decrypt(byte[] input) {
        return encrypt(input);
    }
}
