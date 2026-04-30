package com.cryptomobile.http;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class CryptoHeuristicsTest {

    private static byte[] u(String s) { return s.getBytes(StandardCharsets.UTF_8); }

    // -------- plaintext-looking --------

    @Test
    void empty_is_plaintext() {
        assertTrue(CryptoHeuristics.looksLikePlaintext(new byte[0]));
        assertTrue(CryptoHeuristics.looksLikePlaintext(null));
        assertFalse(CryptoHeuristics.looksLikeCiphertext(new byte[0]));
    }

    @Test
    void json_object_is_plaintext() {
        assertTrue(CryptoHeuristics.looksLikePlaintext(u("{\"id\":1,\"name\":\"bob\"}")));
    }

    @Test
    void json_array_is_plaintext() {
        assertTrue(CryptoHeuristics.looksLikePlaintext(u("[1,2,3,{\"k\":\"v\"}]")));
    }

    @Test
    void xml_doc_is_plaintext() {
        String xml = "<?xml version=\"1.0\"?><root><item>x</item></root>";
        assertTrue(CryptoHeuristics.looksLikePlaintext(u(xml)));
    }

    @Test
    void soap_envelope_is_plaintext() {
        String soap = "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">" +
                "<soap:Body><x/></soap:Body></soap:Envelope>";
        assertTrue(CryptoHeuristics.looksLikePlaintext(u(soap)));
    }

    @Test
    void url_encoded_form_is_plaintext() {
        assertTrue(CryptoHeuristics.looksLikePlaintext(u("a=1&b=hello%20world&c=3")));
    }

    @Test
    void plain_readable_text_is_plaintext() {
        assertTrue(CryptoHeuristics.looksLikePlaintext(u("hello world, this is a readable sentence.\n")));
    }

    // -------- ciphertext-looking --------

    @Test
    void jws_compact_is_ciphertext_ish() {
        // header.payload.signature — three base64url parts
        String jws = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.abcDEF123_-";
        assertFalse(CryptoHeuristics.looksLikePlaintext(u(jws)));
        assertTrue(CryptoHeuristics.looksLikeCiphertext(u(jws)));
    }

    @Test
    void jwe_compact_is_ciphertext_ish() {
        String jwe = "eyJhbGciOiJkaXIifQ.." + "iv_partAA" + "." + "ciph_partBB" + "." + "tag_partCC";
        assertFalse(CryptoHeuristics.looksLikePlaintext(u(jwe)));
    }

    @Test
    void base64_blob_is_ciphertext_ish() {
        byte[] random = new byte[96];
        for (int i = 0; i < random.length; i++) random[i] = (byte) ((i * 31 + 7) & 0xFF);
        String b64 = Base64.getEncoder().encodeToString(random);
        assertFalse(CryptoHeuristics.looksLikePlaintext(u(b64)));
        assertTrue(CryptoHeuristics.looksLikeCiphertext(u(b64)));
    }

    @Test
    void high_entropy_binary_is_ciphertext_ish() {
        byte[] bin = new byte[128];
        // Non-printable, non-UTF8 sequence.
        for (int i = 0; i < bin.length; i++) bin[i] = (byte) ((i * 97 + 13) & 0x7F | 0x80);
        // First byte < 0xC2 so it isn't a UTF-8 multibyte start.
        bin[0] = (byte) 0x81;
        assertFalse(CryptoHeuristics.looksLikePlaintext(bin));
    }

    // -------- negative guards --------

    @Test
    void malformed_json_is_not_accepted_as_json() {
        // Starts with '{' but isn't valid JSON — must not count as plaintext via JSON path.
        // It also isn't XML/url-form; it's short text — might match readable-text fallback
        // if whitespace + printable. Add a binary byte to force the miss.
        byte[] b = new byte[]{ '{', 'a', 'b', 'c', (byte) 0x01, (byte) 0x02, (byte) 0x03 };
        assertFalse(CryptoHeuristics.looksLikePlaintext(b));
    }

    @Test
    void short_random_ascii_is_not_base64_blob() {
        // Length gate: under 16 chars does not count as base64 blob; falls through
        // to readable-text which needs whitespace, so returns false.
        assertFalse(CryptoHeuristics.looksLikePlaintext(u("abcDEF12")));
    }

    @Test
    void invalid_utf8_is_not_plaintext() {
        // 0xC0 followed by an invalid continuation byte → malformed UTF-8.
        // The pre-fix String constructor would have silently substituted U+FFFD
        // and let downstream sniffers misclassify the bytes; the strict UTF-8
        // gate now rejects them outright.
        byte[] invalid = new byte[] { (byte) 0xC0, (byte) 0x28, 'a', 'b', 'c' };
        assertFalse(CryptoHeuristics.looksLikePlaintext(invalid),
                "malformed UTF-8 must not pass the textual gate");
        assertTrue(CryptoHeuristics.looksLikeCiphertext(invalid));
    }

    @Test
    void invalid_utf8_starting_with_brace_is_not_json() {
        // A binary blob whose first byte is 0x7B ('{') used to walk straight
        // into the JSON sniffer. The UTF-8 gate now stops it before that.
        byte[] b = new byte[16];
        b[0] = '{';
        for (int i = 1; i < b.length; i++) b[i] = (byte) (0xF8 | (i & 0x07)); // invalid leading bytes
        assertFalse(CryptoHeuristics.looksLikePlaintext(b));
    }
}
