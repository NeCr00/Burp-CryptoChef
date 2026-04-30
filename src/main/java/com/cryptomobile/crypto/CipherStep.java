package com.cryptomobile.crypto;

/**
 * One stage in an encryption pipeline.
 *
 * <p>Implementations must be stateless w.r.t. the byte arrays they process —
 * they may be invoked concurrently from many HTTP-handler threads.
 * Configuration (keys, IVs, modes) is immutable after construction.
 */
public interface CipherStep {

    /** Short human label used by the UI and error messages. */
    String name();

    /** Transform plaintext to ciphertext/encoded-form. */
    byte[] encrypt(byte[] input) throws CipherStepException;

    /** Inverse of {@link #encrypt(byte[])}. */
    byte[] decrypt(byte[] input) throws CipherStepException;
}
