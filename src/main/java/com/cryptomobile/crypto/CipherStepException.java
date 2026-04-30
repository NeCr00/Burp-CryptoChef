package com.cryptomobile.crypto;

/**
 * Thrown when a pipeline step fails. The message always includes the step
 * name and a human-readable cause, e.g. {@code "AES-CBC: bad padding"}.
 */
public class CipherStepException extends Exception {
    public CipherStepException(String message)                { super(message); }
    public CipherStepException(String message, Throwable t)   { super(message, t); }
}
