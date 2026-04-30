package com.cryptomobile.crypto;

import org.junit.jupiter.api.Test;

import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AesEcbStepTest {

    /** NIST SP 800-38A F.1.5: AES-256-ECB, known answer. */
    @Test
    void nist_sp800_38a_f15_block1() throws Exception {
        byte[] key = HexFormat.of().parseHex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
        byte[] pt  = HexFormat.of().parseHex("6bc1bee22e409f96e93d7e117393172a");
        byte[] expected = HexFormat.of().parseHex("f3eed1bdb5d2a03c064b5a7e3db181f8");

        AesEcbStep step = new AesEcbStep(key);
        byte[] ct = step.encrypt(pt);
        // first 16 bytes of ciphertext must match NIST
        byte[] first = new byte[16];
        System.arraycopy(ct, 0, first, 0, 16);
        assertArrayEquals(expected, first);
        assertTrue(ct.length == 32, "PKCS#7 pads a full block of padding");
        assertArrayEquals(pt, step.decrypt(ct));
    }
}
