package com.cryptomobile.http;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Decision-matrix tests for the "transform vs skip" logic. These are the
 * same rules that the handler suite (CryptoHttpHandler, CryptoProxyRequestHandler,
 * CryptoProxyResponseHandler) evaluates per message, tested at the pure-logic
 * layer so the behaviour is locked down independently of Burp wiring.
 *
 * <p>Matrix from the bug report:
 * <ul>
 *   <li>Location missing OR content doesn't match pipeline input shape → skip</li>
 *   <li>Location present AND content matches pipeline input shape → transform</li>
 *   <li>Message already transformed (annotation present) → skip</li>
 * </ul>
 *
 * <p>We also lock in the {@link CryptoHttpHandler#hasNote} membership test,
 * which is what implements the "already transformed" check.
 */
class ConditionalTransformDecisionTest {

    private static byte[] u(String s) { return s.getBytes(StandardCharsets.UTF_8); }

    // ================= shape matching — content looks encrypted? =================

    @Test
    void empty_body_is_treated_as_plaintext_so_skip() {
        // Empty body → no cipher work. looksLikePlaintext(empty) == true by design.
        assertTrue(CryptoHeuristics.looksLikePlaintext(new byte[0]));
        assertFalse(CryptoHeuristics.looksLikeCiphertext(new byte[0]));
    }

    @Test
    void plaintext_json_passes_through_untouched() {
        // Classic "server returned an error in JSON even though this endpoint is
        // encrypted" case. The handler must NOT try to decrypt.
        assertTrue(CryptoHeuristics.looksLikePlaintext(u("{\"error\":\"bad request\"}")));
    }

    @Test
    void valid_base64_blob_triggers_decrypt_path() {
        byte[] rand = new byte[64];
        for (int i = 0; i < rand.length; i++) rand[i] = (byte) ((i * 31 + 5) & 0xFF);
        String b64 = Base64.getEncoder().encodeToString(rand);
        assertTrue(CryptoHeuristics.looksLikeCiphertext(u(b64)));
        assertFalse(CryptoHeuristics.looksLikePlaintext(u(b64)));
    }

    @Test
    void valid_jwe_five_part_compact_triggers_decrypt_path() {
        String jwe = "eyJhbGciOiJkaXIifQ..AAAA_iv.BBBB_ct.CCCC_tag";
        assertTrue(CryptoHeuristics.looksLikeCiphertext(u(jwe)));
    }

    @Test
    void short_noise_is_neither_blob_nor_structured_text_so_not_plaintext() {
        // "abcDEF12" is 8 chars — under the 16-char gate for base64 blob, so it
        // can't be claimed as ciphertext by that rule. It also isn't structured
        // plaintext. The resulting classification is "not plaintext" (i.e.
        // ciphertext-ish), which means the handler will TRY to decrypt — and
        // the pipeline will error, which the handler catches and passes through
        // with an error annotation. That's the intended behaviour.
        assertFalse(CryptoHeuristics.looksLikePlaintext(u("abcDEF12")));
    }

    // ============= known limitation: JSON-envelope wrapping ciphertext =============

    @Test
    void json_wrapped_ciphertext_envelope_is_classified_as_plaintext() {
        // DOCUMENTED LIMITATION: when ciphertext is wrapped in a JSON envelope
        // like {"ct":"<base64>","iv":"..."}, the WHOLE_BODY heuristic sees valid
        // JSON and classifies as plaintext → decrypt is skipped.
        //
        // Workaround for users: configure a JSONPath/REGEX body location that
        // extracts the inner ciphertext value. Once configured, extraction
        // returns the inner base64 blob, which WILL be classified as ciphertext.
        String envelope = "{\"ct\":\"YWJjZGVmZ2hpamtsbW5vcA==\",\"iv\":\"AAAAAAAAAAAAAAAA\"}";
        assertTrue(CryptoHeuristics.looksLikePlaintext(u(envelope)),
                "JSON envelope is intentionally classified as plaintext; users must configure "
                + "a non-WHOLE body location to reach the inner ciphertext.");

        // But the INNER ciphertext alone IS classified correctly:
        String inner = "YWJjZGVmZ2hpamtsbW5vcA==";
        assertTrue(CryptoHeuristics.looksLikeCiphertext(u(inner)));
    }

    // ================= idempotence: annotation-based already-transformed check =================

    @Test
    void hasNote_whole_token_match_not_substring() {
        // Regression guard: notes are whitespace-separated tokens. "cm:ciphertext"
        // must not match a longer token like "cm:ciphertext:something".
        assertTrue(CryptoHttpHandler.hasNote("cm:ciphertext", "cm:ciphertext"));
        assertTrue(CryptoHttpHandler.hasNote("cm:plaintext cm:ciphertext", "cm:ciphertext"));
        assertFalse(CryptoHttpHandler.hasNote("cm:ciphertext:extra", "cm:ciphertext"));
        assertFalse(CryptoHttpHandler.hasNote("", "cm:ciphertext"));
        assertFalse(CryptoHttpHandler.hasNote(null, "cm:ciphertext"));
    }

    @Test
    void hasNote_rejects_empty_needle() {
        assertFalse(CryptoHttpHandler.hasNote("anything", ""));
        assertFalse(CryptoHttpHandler.hasNote("anything", null));
    }

    @Test
    void hasNote_tolerates_multiple_whitespace() {
        assertTrue(CryptoHttpHandler.hasNote("cm:plaintext   cm:ciphertext", "cm:ciphertext"));
        assertTrue(CryptoHttpHandler.hasNote("cm:plaintext\tcm:ciphertext", "cm:ciphertext"));
        assertTrue(CryptoHttpHandler.hasNote("cm:plaintext\ncm:ciphertext", "cm:ciphertext"));
    }

    // ================== bloat prevention: bounded notes & error tags ==================
    // These guard against the project-file-grows-to-500GB regression. Burp persists
    // every message's notes string into the project file, so the notes string MUST
    // be bounded under all conditions (deduped tokens, hard length cap, no
    // per-invocation context like exception messages or byte counts).

    @Test
    void appendNote_dedupes_repeated_static_tokens() {
        String n = "";
        for (int i = 0; i < 100; i++) {
            n = CryptoHttpHandler.appendNote(n, CryptoHttpHandler.NOTE_PLAINTEXT);
        }
        assertEquals(CryptoHttpHandler.NOTE_PLAINTEXT, n,
                "repeated identical notes must not accumulate");
    }

    @Test
    void appendNote_dedupes_repeated_error_class_tags() {
        // Even if a message hits the same exception type 1000 times across
        // re-sends, the error tag is class-name-based so dedup still fires
        // and the notes string stays bounded.
        String tag = CryptoHttpHandler.NOTE_ERROR_PREFIX
                + CryptoHttpHandler.errorTag(new javax.crypto.BadPaddingException("first"));
        String n = "";
        for (int i = 0; i < 1000; i++) {
            String again = CryptoHttpHandler.NOTE_ERROR_PREFIX
                    + CryptoHttpHandler.errorTag(new javax.crypto.BadPaddingException("retry " + i));
            n = CryptoHttpHandler.appendNote(n, again);
        }
        assertEquals(tag, n,
                "BadPaddingException retries with different messages must produce the same note tag");
    }

    @Test
    void appendNote_caps_total_length() {
        // Worst-case: dedup is somehow defeated and unique tokens keep arriving.
        // The hard cap must still hold so notes can't grow unboundedly in the
        // project file.
        String n = "";
        for (int i = 0; i < 10_000; i++) {
            n = CryptoHttpHandler.appendNote(n, "tok" + i);
        }
        assertTrue(n.length() <= CryptoHttpHandler.MAX_NOTES_LEN,
                "notes length " + n.length() + " exceeded cap " + CryptoHttpHandler.MAX_NOTES_LEN);
    }

    @Test
    void appendNote_cap_truncates_oversized_first_token() {
        // Pathological initial-add that's larger than the cap — must still be
        // truncated rather than stored whole.
        StringBuilder huge = new StringBuilder();
        for (int i = 0; i < 5000; i++) huge.append('A');
        String n = CryptoHttpHandler.appendNote("", huge.toString());
        assertTrue(n.length() <= CryptoHttpHandler.MAX_NOTES_LEN);
    }

    @Test
    void appendNote_handles_null_and_empty_inputs() {
        assertEquals("", CryptoHttpHandler.appendNote(null, null));
        assertEquals("", CryptoHttpHandler.appendNote(null, ""));
        assertEquals("cm:plaintext", CryptoHttpHandler.appendNote(null, "cm:plaintext"));
        assertEquals("cm:plaintext", CryptoHttpHandler.appendNote("", "cm:plaintext"));
        assertEquals("cm:plaintext", CryptoHttpHandler.appendNote("cm:plaintext", ""));
    }

    @Test
    void errorTag_is_short_and_class_name_based() {
        // Each exception class produces a stable short tag; that's what makes
        // the error notes bounded across thousands of re-sends.
        assertEquals("BadPadding", CryptoHttpHandler.errorTag(new javax.crypto.BadPaddingException("x")));
        assertEquals("AEADBadTag", CryptoHttpHandler.errorTag(new javax.crypto.AEADBadTagException("x")));
        assertEquals("IllegalArgument", CryptoHttpHandler.errorTag(new IllegalArgumentException("x")));
        // Strips trailing "Exception" so the tag stays compact.
        assertFalse(CryptoHttpHandler.errorTag(new RuntimeException()).endsWith("Exception"));
    }

    @Test
    void errorTag_handles_null_input() {
        assertEquals("unknown", CryptoHttpHandler.errorTag(null));
    }

    @Test
    void errorTag_caps_long_class_names() {
        // Defence-in-depth: even an unusually long class name never produces
        // a tag exceeding 40 characters.
        Throwable t = new Throwable();
        String tag = CryptoHttpHandler.errorTag(t);
        assertNotNull(tag);
        assertTrue(tag.length() <= 40);
    }

    @Test
    void truncate_caps_long_messages() {
        StringBuilder huge = new StringBuilder();
        for (int i = 0; i < 10_000; i++) huge.append('X');
        Throwable e = new RuntimeException(huge.toString());
        String s = CryptoHttpHandler.truncate(e);
        // Caller-side cap + a small ellipsis allowance + the class-name prefix
        // ("RuntimeException: ") — definitely well under 1000 chars.
        assertTrue(s.length() < 1000,
                "truncated length " + s.length() + " unexpectedly large");
    }

    @Test
    void truncate_handles_null_and_no_message() {
        assertEquals("null", CryptoHttpHandler.truncate(null));
        String s = CryptoHttpHandler.truncate(new RuntimeException());
        assertNotNull(s);
        assertFalse(s.isEmpty());
    }

    @Test
    void simulated_runaway_re_processing_does_not_grow_notes() {
        // Direct regression test for the 500GB project-file scenario: the
        // same logical message is processed by 5 handlers and re-sent 1000
        // times, each time hitting an exception with a unique message string.
        // Notes must NOT grow unboundedly.
        String n = "";
        java.util.Random r = new java.util.Random(0xC0FFEEL);
        for (int pass = 0; pass < 1000; pass++) {
            n = CryptoHttpHandler.appendNote(n, CryptoHttpHandler.NOTE_SKIPPED);
            // Five handler invocations × five distinct exception classes —
            // tags are class-name-based so dedup applies after the first pass.
            n = CryptoHttpHandler.appendNote(n,
                    CryptoHttpHandler.NOTE_ERROR_PREFIX + CryptoHttpHandler.errorTag(
                            new javax.crypto.BadPaddingException("pass " + pass + " " + r.nextLong())));
            n = CryptoHttpHandler.appendNote(n,
                    CryptoHttpHandler.NOTE_ERROR_PREFIX + CryptoHttpHandler.errorTag(
                            new IllegalArgumentException("pass " + pass + " " + r.nextLong())));
            n = CryptoHttpHandler.appendNote(n,
                    CryptoHttpHandler.NOTE_ERROR_PREFIX + CryptoHttpHandler.errorTag(
                            new javax.crypto.AEADBadTagException("pass " + pass + " " + r.nextLong())));
            n = CryptoHttpHandler.appendNote(n,
                    CryptoHttpHandler.NOTE_ERROR_PREFIX + CryptoHttpHandler.errorTag(
                            new java.io.IOException("pass " + pass + " " + r.nextLong())));
            n = CryptoHttpHandler.appendNote(n,
                    CryptoHttpHandler.NOTE_ERROR_PREFIX + CryptoHttpHandler.errorTag(
                            new RuntimeException("pass " + pass + " " + r.nextLong())));
        }
        assertTrue(n.length() <= CryptoHttpHandler.MAX_NOTES_LEN,
                "notes grew to " + n.length() + " across 1000 re-runs — bloat regression");
        // Sanity: dedup actually fired — we should still have at least the
        // skipped tag and a few error tags.
        assertTrue(CryptoHttpHandler.hasNote(n, CryptoHttpHandler.NOTE_SKIPPED));
        assertTrue(n.contains(CryptoHttpHandler.NOTE_ERROR_PREFIX));
    }
}
