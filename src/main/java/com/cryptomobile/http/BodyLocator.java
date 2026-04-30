package com.cryptomobile.http;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.cryptomobile.config.Config;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Extract and reinsert ciphertext blobs at a configurable location within an
 * HTTP message. Three locations are supported — in order of recommendation:
 *
 * <ol>
 *     <li>{@code whole} — the entire HTTP body (default, recommended).</li>
 *     <li>{@code header} — a single header value.</li>
 *     <li>{@code regex} — capture group 1 of a regex over the body
 *         (last resort, for messages that wrap ciphertext in a larger envelope).</li>
 * </ol>
 */
public final class BodyLocator {

    private BodyLocator() {}

    /** Cache for regex body-location patterns. Same rationale as
     *  {@link ScopeMatcher}: extraction runs on every in-scope message, so
     *  recompiling per-call burned CPU on busy targets. */
    private static final ConcurrentHashMap<String, Pattern> patternCache = new ConcurrentHashMap<>();

    /** Result of extraction: the ciphertext bytes, plus an opaque handle the
     *  caller passes back to {@link #reinsertIntoRequest}/{@link #reinsertIntoResponse}. */
    public static final class Extract {
        public final byte[] ciphertext;
        public final Object handle;
        public Extract(byte[] ciphertext, Object handle) {
            this.ciphertext = ciphertext;
            this.handle = handle;
        }
    }

    public static Extract extractFromRequest(HttpRequest req, Config.BodyLocation loc) {
        return extract(req.body().getBytes(), req, loc, true);
    }
    public static HttpRequest reinsertIntoRequest(HttpRequest req, Config.BodyLocation loc, byte[] replacement, Extract prior) {
        return (HttpRequest) reinsert(req, loc, replacement, prior, true);
    }
    public static Extract extractFromResponse(HttpResponse res, Config.BodyLocation loc) {
        return extract(res.body().getBytes(), res, loc, false);
    }
    public static HttpResponse reinsertIntoResponse(HttpResponse res, Config.BodyLocation loc, byte[] replacement, Extract prior) {
        return (HttpResponse) reinsert(res, loc, replacement, prior, false);
    }

    // ================= shared =================
    private static Extract extract(byte[] body, Object msg, Config.BodyLocation loc, boolean isRequest) {
        String kind = normalise(loc);
        switch (kind) {
            case "whole":
                return new Extract(trimTrailingNewlinesIfTextual(body), new WholeHandle());
            case "header": {
                String h = headerValue(msg, loc.expression, isRequest);
                if (h == null) return null;
                // Header values are already structurally trimmed by HTTP parsing,
                // but be defensive: a folded header or CRLF-terminated value can
                // occasionally leak in.
                byte[] hb = trimTrailingNewlinesIfTextual(h.getBytes(StandardCharsets.UTF_8));
                return new Extract(hb, new HeaderHandle(loc.expression));
            }
            case "regex": {
                Pattern p = compileCached(loc.expression);
                if (p == null) return null;
                String src = new String(body, StandardCharsets.UTF_8);
                Matcher m = p.matcher(src);
                if (!m.find()) return null;
                int start, end;
                String captured;
                if (m.groupCount() < 1) {
                    captured = m.group();
                    start = m.start();
                    end   = m.end();
                } else {
                    captured = m.group(1);
                    start = m.start(1);
                    end   = m.end(1);
                }
                if (captured == null) return null;
                byte[] cb = trimTrailingNewlinesIfTextual(captured.getBytes(StandardCharsets.UTF_8));
                return new Extract(cb, new RegexHandle(loc.expression, start, end));
            }
            default:
                return null;
        }
    }

    /**
     * Strip trailing CR/LF bytes from {@code data} iff the bytes look textual
     * (printable ASCII + tab/CR/LF only). Raw binary ciphertext is left alone.
     *
     * <p>Background: on some Burp-on-Linux installs (e.g. Kali running Burp
     * Suite Pro under the system OpenJDK), the wire body returned by
     * {@code request.body().getBytes()} carries a trailing {@code 0x0A} that
     * is not part of the actual ciphertext. The same traffic on Burp-on-macOS
     * yields bytes without that trailing newline. Stripping defensively at
     * extraction time makes the pipeline platform-independent without risking
     * a binary-data false-positive: a genuine raw binary AES ciphertext is
     * effectively guaranteed to contain at least one byte outside the
     * printable-ASCII range, so the textual gate refuses to touch it.
     *
     * <p>Steps that decode text input (Base64, JWE, EncodingAdapter) already
     * call {@code .trim()} / {@code replaceAll("\\s+", "")} internally and are
     * unaffected by this trim. The change matters for pipelines whose first
     * decrypt step is a raw binary cipher (AES-CBC/GCM/ECB, XOR, RSA-OAEP),
     * where a stray trailing {@code \n} otherwise produces a block-size
     * mismatch or auth-tag failure.
     */
    static byte[] trimTrailingNewlinesIfTextual(byte[] data) {
        if (data == null || data.length == 0) return data;
        int last = data.length;
        while (last > 0 && (data[last - 1] == 0x0A || data[last - 1] == 0x0D)) last--;
        if (last == data.length) return data;     // nothing to trim
        if (!isLikelyTextual(data)) return data;  // binary body — hands off
        byte[] out = new byte[last];
        System.arraycopy(data, 0, out, 0, last);
        return out;
    }

    /**
     * @return {@code true} if every byte is either printable ASCII (0x20..0x7E)
     *         or one of TAB / LF / CR. Anything else (including UTF-8
     *         multi-byte continuation bytes) is treated as binary so we don't
     *         accidentally trim a raw cipher byte stream.
     */
    private static boolean isLikelyTextual(byte[] data) {
        for (byte v : data) {
            int b = v & 0xFF;
            if (b == 0x09 || b == 0x0A || b == 0x0D) continue;
            if (b >= 0x20 && b <= 0x7E) continue;
            return false;
        }
        return true;
    }

    private static Object reinsert(Object msg, Config.BodyLocation loc, byte[] replacement, Extract prior, boolean isRequest) {
        String kind = normalise(loc);
        byte[] body = isRequest ? ((HttpRequest) msg).body().getBytes() : ((HttpResponse) msg).body().getBytes();

        switch (kind) {
            case "whole":
                return isRequest
                        ? ((HttpRequest) msg).withBody(burp.api.montoya.core.ByteArray.byteArray(replacement))
                        : ((HttpResponse) msg).withBody(burp.api.montoya.core.ByteArray.byteArray(replacement));
            case "header": {
                String newValue = new String(replacement, StandardCharsets.UTF_8);
                return isRequest
                        ? ((HttpRequest) msg).withUpdatedHeader(loc.expression, newValue)
                        : ((HttpResponse) msg).withUpdatedHeader(loc.expression, newValue);
            }
            case "regex": {
                if (!(prior != null && prior.handle instanceof RegexHandle)) return msg;
                RegexHandle h = (RegexHandle) prior.handle;
                byte[] newBody = spliceBytes(body, h.start, h.end, replacement);
                return isRequest
                        ? ((HttpRequest) msg).withBody(burp.api.montoya.core.ByteArray.byteArray(newBody))
                        : ((HttpResponse) msg).withBody(burp.api.montoya.core.ByteArray.byteArray(newBody));
            }
            default:
                return msg;
        }
    }

    /** Map any legacy kind to one of the three supported kinds. */
    private static String normalise(Config.BodyLocation loc) {
        if (loc == null || loc.kind == null) return "whole";
        String k = loc.kind.toLowerCase();
        return switch (k) {
            case "whole"  -> "whole";
            case "header" -> "header";
            case "regex"  -> "regex";
            default       -> "whole"; // jsonpath / xpath / form-param from older configs collapse to whole
        };
    }

    private static String headerValue(Object msg, String name, boolean isRequest) {
        if (name == null || name.isBlank()) return null;
        java.util.List<HttpHeader> headers = isRequest
                ? ((HttpRequest) msg).headers()
                : ((HttpResponse) msg).headers();
        for (HttpHeader h : headers) if (h.name().equalsIgnoreCase(name)) return h.value();
        return null;
    }

    /** Compile or return a cached {@code DOTALL} pattern for a regex body
     *  location. Returns {@code null} on {@link PatternSyntaxException} so
     *  the caller can pass the message through untouched rather than throwing. */
    private static Pattern compileCached(String regex) {
        if (regex == null || regex.isEmpty()) return null;
        Pattern p = patternCache.get(regex);
        if (p != null) return p;
        try {
            p = Pattern.compile(regex, Pattern.DOTALL);
        } catch (PatternSyntaxException pse) {
            return null;
        }
        patternCache.put(regex, p);
        return p;
    }

    /** Splice {@code replacement} into {@code body[start:end]}. */
    public static byte[] spliceBytes(byte[] body, int start, int end, byte[] replacement) {
        if (start < 0) start = 0;
        if (end > body.length) end = body.length;
        if (start > end) start = end;
        byte[] out = new byte[start + replacement.length + (body.length - end)];
        System.arraycopy(body, 0, out, 0, start);
        System.arraycopy(replacement, 0, out, start, replacement.length);
        System.arraycopy(body, end, out, start + replacement.length, body.length - end);
        return out;
    }

    // ================== opaque handles ==================
    private static final class WholeHandle {}
    private static final class HeaderHandle { final String name; HeaderHandle(String n) { this.name = n; } }
    private static final class RegexHandle  {
        final String expr; final int start; final int end;
        RegexHandle(String e, int s, int en) { this.expr = e; this.start = s; this.end = en; }
    }
}
