package com.cryptomobile.http;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the byte-splice primitive that underpins REGEX reinsertion. The
 * Montoya-typed round-trip (extract → reinsert on a real HttpRequest) is
 * covered by the integration test suite against a live Burp instance, since
 * HttpRequest has no standalone reference implementation available to tests.
 */
class BodyLocatorTest {

    private static byte[] u(String s) { return s.getBytes(StandardCharsets.UTF_8); }
    private static String s(byte[] b) { return new String(b, StandardCharsets.UTF_8); }

    @Test
    void splice_middle_preserves_surroundings() {
        byte[] body = u("{\"ct\":\"AAAA\",\"n\":1}");
        int start = body.length - 10 /* pos of first A */ - 1;
        // locate start/end of "AAAA" deterministically
        String orig = s(body);
        int aStart = orig.indexOf("AAAA");
        int aEnd   = aStart + "AAAA".length();

        byte[] out = BodyLocator.spliceBytes(body, aStart, aEnd, u("XYZ"));
        assertEquals("{\"ct\":\"XYZ\",\"n\":1}", s(out));
    }

    @Test
    void splice_whole_body_replaces_entirely() {
        byte[] body = u("hello");
        byte[] out  = BodyLocator.spliceBytes(body, 0, body.length, u("world!"));
        assertEquals("world!", s(out));
    }

    @Test
    void splice_empty_replacement_deletes_range() {
        byte[] body = u("abcXYZdef");
        byte[] out  = BodyLocator.spliceBytes(body, 3, 6, new byte[0]);
        assertEquals("abcdef", s(out));
    }

    @Test
    void splice_longer_replacement_grows_output() {
        byte[] body = u("[X]");
        byte[] out  = BodyLocator.spliceBytes(body, 1, 2, u("PLAINTEXT"));
        assertEquals("[PLAINTEXT]", s(out));
    }

    @Test
    void splice_oob_indices_are_clamped() {
        byte[] body = u("abc");
        byte[] out  = BodyLocator.spliceBytes(body, -5, 99, u("Z"));
        assertEquals("Z", s(out));
    }

    @Test
    void splice_roundtrip_identity_when_replacement_equals_range() {
        byte[] body = u("header:{inner}:tail");
        int start = s(body).indexOf("inner");
        int end   = start + "inner".length();
        byte[] extracted = new byte[end - start];
        System.arraycopy(body, start, extracted, 0, extracted.length);

        byte[] roundtripped = BodyLocator.spliceBytes(body, start, end, extracted);
        assertArrayEquals(body, roundtripped);
    }

    @Test
    void splice_start_greater_than_end_clamps() {
        byte[] body = u("abc");
        // start=3, end=1 → end is NOT greater than body.length so stays 1;
        // start is clamped down to end=1; effective [1,1] → inserts replacement
        // at position 1 without deleting anything.
        byte[] out  = BodyLocator.spliceBytes(body, 3, 1, u("Z"));
        assertEquals("aZbc", s(out));
    }

    // =================== trimTrailingNewlinesIfTextual ===================
    // Regression guard for the Linux-vs-macOS body-extraction quirk: on some
    // Burp-on-Linux installs, request.body().getBytes() yields a trailing 0x0A
    // that's not present on macOS. We trim defensively at extract time, but
    // ONLY when the bytes look textual (so we never corrupt a raw-binary
    // ciphertext whose final byte happens to be 0x0A).

    @Test
    void trim_strips_trailing_lf_from_base64_blob() {
        byte[] in  = u("YWJjZGVmZ2hpamtsbW5vcA==\n");
        byte[] out = BodyLocator.trimTrailingNewlinesIfTextual(in);
        assertEquals("YWJjZGVmZ2hpamtsbW5vcA==", s(out));
    }

    @Test
    void trim_strips_trailing_crlf_from_base64_blob() {
        byte[] in  = u("YWJjZGVmZ2hpamtsbW5vcA==\r\n");
        byte[] out = BodyLocator.trimTrailingNewlinesIfTextual(in);
        assertEquals("YWJjZGVmZ2hpamtsbW5vcA==", s(out));
    }

    @Test
    void trim_strips_multiple_trailing_newlines() {
        byte[] in  = u("hex0123abcd\n\n\n");
        byte[] out = BodyLocator.trimTrailingNewlinesIfTextual(in);
        assertEquals("hex0123abcd", s(out));
    }

    @Test
    void trim_leaves_textual_body_with_no_trailing_newline() {
        byte[] in  = u("YWJjZGVmZ2hpamtsbW5vcA==");
        byte[] out = BodyLocator.trimTrailingNewlinesIfTextual(in);
        // Same instance — nothing to do.
        assertSame(in, out);
    }

    @Test
    void trim_preserves_interior_newlines() {
        // PEM-style multi-line base64 — interior \n must survive; only the
        // trailing one gets stripped.
        byte[] in  = u("AAAA\nBBBB\nCCCC\n");
        byte[] out = BodyLocator.trimTrailingNewlinesIfTextual(in);
        assertEquals("AAAA\nBBBB\nCCCC", s(out));
    }

    @Test
    void trim_does_not_touch_binary_body_ending_in_0x0A() {
        // Raw 32-byte AES ciphertext whose last byte happens to be 0x0A.
        // Trimming would shift the block boundary and corrupt decryption, so
        // the textual gate must refuse.
        byte[] in = new byte[32];
        for (int i = 0; i < 31; i++) in[i] = (byte) ((i * 137 + 3) & 0xFF);
        in[31] = 0x0A;
        byte[] out = BodyLocator.trimTrailingNewlinesIfTextual(in);
        assertSame(in, out, "binary input must be returned unchanged");
        assertEquals(32, out.length);
        assertEquals((byte) 0x0A, out[31]);
    }

    @Test
    void trim_does_not_touch_random_iv_prepended_aes_blob() {
        // 16-byte random IV + 16-byte ciphertext. A high-bit byte at index 0
        // is enough to flip the textual gate to "binary" → input untouched.
        byte[] in = new byte[32];
        in[0]  = (byte) 0xFF;
        in[31] = 0x0A;
        byte[] out = BodyLocator.trimTrailingNewlinesIfTextual(in);
        assertSame(in, out);
    }

    @Test
    void trim_returns_input_unchanged_on_empty_or_null() {
        assertNull(BodyLocator.trimTrailingNewlinesIfTextual(null));
        byte[] empty = new byte[0];
        assertSame(empty, BodyLocator.trimTrailingNewlinesIfTextual(empty));
    }

    @Test
    void trim_handles_textual_body_that_is_only_newlines() {
        // Pathological input: trims down to empty. The handler's empty-body
        // guard then kicks in and skips with cm:skipped.
        byte[] in  = u("\n\n\n");
        byte[] out = BodyLocator.trimTrailingNewlinesIfTextual(in);
        assertEquals(0, out.length);
    }

    @Test
    void trim_strips_trailing_lf_from_jwe_compact() {
        // Five-part dotted base64url. Without trimming, Nimbus's
        // JWEObject.parse rejects the trailing whitespace.
        byte[] in  = u("eyJhbGciOiJkaXIifQ..AAAA_iv.BBBB_ct.CCCC_tag\n");
        byte[] out = BodyLocator.trimTrailingNewlinesIfTextual(in);
        assertEquals("eyJhbGciOiJkaXIifQ..AAAA_iv.BBBB_ct.CCCC_tag", s(out));
    }

    @Test
    void trim_keeps_utf8_multibyte_body_intact() {
        // UTF-8 multi-byte sequences contain bytes >= 0xC2; the textual gate
        // refuses, so a high-bit body is left alone even if it ends with 0x0A.
        byte[] in = "héllo\n".getBytes(StandardCharsets.UTF_8);
        byte[] out = BodyLocator.trimTrailingNewlinesIfTextual(in);
        assertSame(in, out);
    }
}
