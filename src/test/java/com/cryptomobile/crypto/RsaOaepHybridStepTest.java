package com.cryptomobile.crypto;

import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

import static org.junit.jupiter.api.Assertions.*;

class RsaOaepHybridStepTest {

    @Test
    void round_trip_rsa_oaep_gcm() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        RsaOaepHybridStep step = new RsaOaepHybridStep(
                kp.getPublic(), kp.getPrivate(),
                "SHA-256", "SHA-256", 32, RsaOaepHybridStep.Inner.AES_GCM);
        byte[] plain = "hybrid AES-GCM under RSA-OAEP-256".getBytes();
        byte[] cipher = step.encrypt(plain);
        assertArrayEquals(plain, step.decrypt(cipher));
    }

    @Test
    void round_trip_rsa_oaep_cbc() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        RsaOaepHybridStep step = new RsaOaepHybridStep(
                kp.getPublic(), kp.getPrivate(),
                "SHA-1", "SHA-1", 16, RsaOaepHybridStep.Inner.AES_CBC);
        byte[] plain = "AES-128-CBC under RSA-OAEP-SHA-1".getBytes();
        byte[] cipher = step.encrypt(plain);
        assertArrayEquals(plain, step.decrypt(cipher));
    }

    @Test
    void missing_private_key_fails_cleanly() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        RsaOaepHybridStep step = new RsaOaepHybridStep(
                kp.getPublic(), null, "SHA-256", "SHA-256", 32, RsaOaepHybridStep.Inner.AES_GCM);
        byte[] cipher = step.encrypt("hi".getBytes());
        CipherStepException e = assertThrows(CipherStepException.class, () -> step.decrypt(cipher));
        assertTrue(e.getMessage().contains("no RSA private key"));
    }
}
