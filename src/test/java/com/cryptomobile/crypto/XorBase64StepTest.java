package com.cryptomobile.crypto;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class XorBase64StepTest {

    @Test
    void xor_repeat_mode() throws Exception {
        XorStep step = new XorStep("ABC".getBytes(StandardCharsets.UTF_8), XorStep.RepeatMode.REPEAT);
        byte[] in  = "Hello, world".getBytes();
        byte[] out = step.encrypt(in);
        assertArrayEquals(in, step.decrypt(out), "XOR must be self-inverse");
    }

    @Test
    void xor_truncate_mode() throws Exception {
        XorStep step = new XorStep("k".getBytes(), XorStep.RepeatMode.TRUNCATE);
        byte[] out = step.encrypt("ab".getBytes());
        // only byte 0 is XORed
        assertEquals((byte) ('a' ^ 'k'), out[0]);
        assertEquals((byte) 'b', out[1]);
    }

    @Test
    void base64_standard_round_trip() throws Exception {
        Base64Step step = new Base64Step(Base64Step.Variant.STANDARD, true);
        byte[] in = "hello".getBytes();
        byte[] enc = step.encrypt(in);
        assertEquals("aGVsbG8=", new String(enc, StandardCharsets.US_ASCII));
        assertArrayEquals(in, step.decrypt(enc));
    }

    @Test
    void base64_url_without_padding() throws Exception {
        Base64Step step = new Base64Step(Base64Step.Variant.URL_SAFE, false);
        byte[] in = new byte[]{(byte) 0xFB, (byte) 0xFF, (byte) 0xFE};
        byte[] enc = step.encrypt(in);
        assertEquals("-__-", new String(enc, StandardCharsets.US_ASCII));
        assertArrayEquals(in, step.decrypt(enc));
    }

    @Test
    void base64_tolerant_decoder_accepts_whitespace_and_no_padding() throws Exception {
        Base64Step step = new Base64Step(Base64Step.Variant.STANDARD, true);
        byte[] dec = step.decrypt("aGVs\n\nbG8".getBytes(StandardCharsets.US_ASCII));
        assertArrayEquals("hello".getBytes(), dec);
    }
}
