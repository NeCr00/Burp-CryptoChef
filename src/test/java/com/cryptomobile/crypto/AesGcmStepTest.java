package com.cryptomobile.crypto;

import org.junit.jupiter.api.Test;

import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class AesGcmStepTest {

    /** NIST GCM test vector (AES-256-GCM) — test case 14 from "gcm-spec.pdf".
     *  Key: 0*32; IV: 0*12; Plaintext: 0*16; AAD: empty. */
    @Test
    void nist_gcm_test_case_14() throws Exception {
        byte[] key = new byte[32];
        byte[] iv  = new byte[12];
        byte[] pt  = new byte[16];
        // Known ciphertext || tag for this vector (32 bytes total):
        byte[] expected = HexFormat.of().parseHex(
                "cea7403d4d606b6e074ec5d3baf39d18" + "d0d1c8a799996bf0265b98b5d48ab919");

        AesGcmStep step = new AesGcmStep(key, iv, null, AesGcmStep.NonceMode.FIXED);
        byte[] ct = step.encrypt(pt);
        assertArrayEquals(expected, ct);
        assertArrayEquals(pt, step.decrypt(ct));
    }

    @Test
    void random_nonce_round_trip() throws Exception {
        Map<String, String> p = new LinkedHashMap<>();
        p.put("key", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        p.put("key-encoding", "hex");
        p.put("nonce-mode", "random");
        AesGcmStep step = AesGcmStep.fromParams(p, 256);
        byte[] plain = "GCM round trip".getBytes();
        byte[] ct = step.encrypt(plain);
        assertTrue(ct.length >= 12 + plain.length + 16, "must include nonce + tag");
        assertArrayEquals(plain, step.decrypt(ct));
    }

    @Test
    void tampered_tag_is_caught() throws Exception {
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        AesGcmStep step = new AesGcmStep(key, nonce, null, AesGcmStep.NonceMode.FIXED);
        byte[] ct = step.encrypt("secret".getBytes());
        ct[ct.length - 1] ^= 0x01;
        CipherStepException e = assertThrows(CipherStepException.class, () -> step.decrypt(ct));
        assertTrue(e.getMessage().contains("authentication tag mismatch"));
    }
}
