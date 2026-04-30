package com.cryptomobile.crypto;

import org.junit.jupiter.api.Test;

import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class AesCbcStepTest {

    /** NIST SP 800-38A F.2.5: AES-256-CBC, single-block, known answer. */
    @Test
    void nist_sp800_38a_f25_block1() throws Exception {
        byte[] key = HexFormat.of().parseHex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
        byte[] iv  = HexFormat.of().parseHex("000102030405060708090a0b0c0d0e0f");
        byte[] pt  = HexFormat.of().parseHex("6bc1bee22e409f96e93d7e117393172a");
        // Expected CBC ciphertext (first block only, NO padding)
        byte[] expectedNoPad = HexFormat.of().parseHex("f58c4c04d6e5f1ba779eabfb5f7bfbd6");

        // Our step uses PKCS#7, so encrypt a single 16-byte block → 32 bytes out.
        // Verify the first block matches NIST.
        AesCbcStep step = new AesCbcStep(key, iv, AesCbcStep.IvMode.FIXED);
        byte[] ct = step.encrypt(pt);
        assertEquals(32, ct.length);
        byte[] first = new byte[16];
        System.arraycopy(ct, 0, first, 0, 16);
        assertArrayEquals(expectedNoPad, first, "first CBC block must match NIST vector");

        // Round-trip
        assertArrayEquals(pt, step.decrypt(ct));
    }

    @Test
    void round_trip_random_iv_mode() throws Exception {
        Map<String, String> p = new LinkedHashMap<>();
        p.put("key", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        p.put("key-encoding", "hex");
        p.put("iv-mode", "random");

        AesCbcStep step = AesCbcStep.fromParams(p, 256);
        byte[] plain = "hello CryptoChef, this is a test of AES-256-CBC with a prepended IV"
                .getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] ct = step.encrypt(plain);
        assertTrue(ct.length >= 16 + 16, "must include 16-byte IV + >=1 block");
        assertArrayEquals(plain, step.decrypt(ct));
    }

    @Test
    void bad_padding_is_reported() throws Exception {
        byte[] key = new byte[32];
        byte[] iv  = new byte[16];
        AesCbcStep step = new AesCbcStep(key, iv, AesCbcStep.IvMode.FIXED);
        byte[] ct = step.encrypt("hi".getBytes());
        ct[ct.length - 1] ^= 0x01;
        CipherStepException e = assertThrows(CipherStepException.class, () -> step.decrypt(ct));
        assertTrue(e.getMessage().contains("bad padding"));
    }

    @Test
    void rejects_wrong_key_size() {
        assertThrows(CipherStepException.class, () -> new AesCbcStep(new byte[20], new byte[16], AesCbcStep.IvMode.FIXED));
    }
}
