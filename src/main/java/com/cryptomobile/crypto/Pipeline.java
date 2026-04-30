package com.cryptomobile.crypto;

import com.cryptomobile.config.Config;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * An ordered list of {@link CipherStep}s.
 *
 * <p>Encryption runs steps in the order given (top to bottom). Decryption
 * runs the inverse of each step in reverse order. Intermediate outputs
 * can be captured for debugging via {@link #encryptWithTrace(byte[])} /
 * {@link #decryptWithTrace(byte[])}.
 *
 * <p>The plugin builds pipelines from the persisted config via
 * {@link #fromConfig(Config.NamedPipeline, Config)}.
 */
public final class Pipeline {

    /** One intermediate stage — step name + output bytes. */
    public record Stage(String stepName, byte[] output) {}

    private final List<CipherStep> steps;

    public Pipeline(List<CipherStep> steps) {
        this.steps = List.copyOf(steps);
    }

    public int size() { return steps.size(); }
    public List<CipherStep> steps() { return steps; }

    // ===================== public API =====================

    public byte[] encrypt(byte[] input) throws CipherStepException {
        byte[] cur = input;
        for (CipherStep s : steps) cur = s.encrypt(cur);
        return cur;
    }

    public byte[] decrypt(byte[] input) throws CipherStepException {
        byte[] cur = input;
        for (int i = steps.size() - 1; i >= 0; i--) cur = steps.get(i).decrypt(cur);
        return cur;
    }

    public List<Stage> encryptWithTrace(byte[] input) throws CipherStepException {
        List<Stage> trace = new ArrayList<>(steps.size());
        byte[] cur = input;
        for (CipherStep s : steps) {
            cur = s.encrypt(cur);
            trace.add(new Stage(s.name() + ".encrypt", cur));
        }
        return trace;
    }

    public List<Stage> decryptWithTrace(byte[] input) throws CipherStepException {
        List<Stage> trace = new ArrayList<>(steps.size());
        byte[] cur = input;
        for (int i = steps.size() - 1; i >= 0; i--) {
            CipherStep s = steps.get(i);
            cur = s.decrypt(cur);
            trace.add(new Stage(s.name() + ".decrypt", cur));
        }
        return trace;
    }

    // ===================== factory =====================

    /**
     * Build a {@link Pipeline} from a {@link Config.NamedPipeline}, resolving
     * named keys in the supplied {@link Config} if a step refers to one.
     */
    public static Pipeline fromConfig(Config.NamedPipeline np, Config cfg) throws CipherStepException {
        if (np == null) return new Pipeline(Collections.emptyList());
        List<CipherStep> out = new ArrayList<>(np.steps.size());
        for (Config.PipelineStep ps : np.steps) {
            if (!ps.enabled) continue;
            Map<String, String> p = resolveKeyReferences(ps.params, cfg);
            CipherStep step = buildStep(ps.type, p);
            String inEnc  = p.getOrDefault("input-encoding",  "raw");
            String outEnc = p.getOrDefault("output-encoding", "raw");
            if (!"raw".equalsIgnoreCase(inEnc) || !"raw".equalsIgnoreCase(outEnc)) {
                step = new EncodingAdapterStep(step, inEnc, outEnc);
            }
            out.add(step);
        }
        return new Pipeline(out);
    }

    private static CipherStep buildStep(String type, Map<String, String> p) throws CipherStepException {
        if (type == null) throw new CipherStepException("pipeline step has no type");
        switch (type.toUpperCase()) {
            case "AES-256-CBC":  return AesCbcStep.fromParams(p, 256);
            case "AES-128-CBC":  return AesCbcStep.fromParams(p, 128);
            case "AES-CBC":      return AesCbcStep.fromParams(p, -1);
            case "AES-256-GCM":  return AesGcmStep.fromParams(p, 256);
            case "AES-128-GCM":  return AesGcmStep.fromParams(p, 128);
            case "AES-GCM":      return AesGcmStep.fromParams(p, -1);
            case "AES-256-ECB":  return AesEcbStep.fromParams(p, 256);
            case "AES-128-ECB":  return AesEcbStep.fromParams(p, 128);
            case "AES-ECB":      return AesEcbStep.fromParams(p, -1);
            case "RSA-OAEP-HYBRID": return RsaOaepHybridStep.fromParams(p);
            case "JWE":          return JweStep.fromParams(p);
            case "XOR":          return XorStep.fromParams(p);
            case "BASE64":       return Base64Step.fromParams(p);
            default:             throw new CipherStepException("unknown step type: " + type);
        }
    }

    /**
     * If a param like {@code "key-ref"} is set and names an entry in the
     * keystore, resolve it into the actual {@code "key"} param. This lets
     * multiple steps share the same material without copy-paste.
     */
    private static Map<String, String> resolveKeyReferences(Map<String, String> params, Config cfg) {
        Map<String, String> p = new java.util.LinkedHashMap<>(params);
        resolveRef(p, "key-ref",             "key",             "key-encoding", cfg);
        resolveRef(p, "iv-ref",              "iv",              "iv-encoding", cfg);
        resolveRef(p, "nonce-ref",           "nonce",           "nonce-encoding", cfg);
        resolveRef(p, "public-key-ref",      "public-key-pem",  null, cfg);
        resolveRef(p, "private-key-ref",     "private-key-pem", null, cfg);
        resolveRef(p, "jwk-public-ref",      "jwk-public",      null, cfg);
        resolveRef(p, "jwk-private-ref",     "jwk-private",     null, cfg);
        return p;
    }

    private static void resolveRef(Map<String, String> p, String refParam, String targetParam,
                                   String encodingParam, Config cfg) {
        String refName = p.get(refParam);
        if (refName == null || refName.isBlank()) return;
        Config.NamedKey k = cfg.findKey(refName);
        if (k == null) return; // leave as-is; buildStep will fail with a clear message if required
        p.putIfAbsent(targetParam, k.material);
        if (encodingParam != null) p.putIfAbsent(encodingParam, k.encoding);
    }
}
