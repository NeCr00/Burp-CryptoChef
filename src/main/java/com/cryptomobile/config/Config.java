package com.cryptomobile.config;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Top-level serializable configuration POJO for the CryptoChef extension.
 *
 * Persisted as a single JSON blob via {@link ConfigStore} using Burp's
 * {@code api.persistence().extensionData()} {@code PersistedObject}.
 *
 * All fields are public to keep Gson serialization trivial. Do not mutate
 * instances concurrently — {@link ConfigStore} guards reads/writes with a
 * {@link java.util.concurrent.locks.ReadWriteLock}.
 */
public final class Config {

    /** One named entry in the pipeline that a scope refers to. */
    public static final class PipelineStep {
        public String type;               // "AES-CBC", "AES-GCM", "AES-ECB", "RSA-OAEP-HYBRID", "JWE", "XOR", "BASE64"
        public boolean enabled = true;
        /** Free-form parameters; interpreted by the matching CipherStep factory. */
        public Map<String, String> params = new LinkedHashMap<>();

        public PipelineStep() {}
        public PipelineStep(String type) { this.type = type; }
    }

    /** A named pipeline bound to a scope. */
    public static final class NamedPipeline {
        public String name;
        public List<PipelineStep> steps = new ArrayList<>();

        public NamedPipeline() {}
        public NamedPipeline(String name) { this.name = name; }
    }

    /** A scope rule that picks a pipeline for matching hosts/URLs. */
    public static final class ScopeRule {
        /** "wildcard", "regex", or "burp-target" (reuses Burp's Target Scope). */
        public String matchKind = "wildcard";
        /** Pattern — host or URL matcher; ignored for "burp-target". */
        public String pattern = "";
        /** Reference to a NamedPipeline by name. */
        public String pipelineName;
        public boolean enabled = true;
        /** Where in the message the ciphertext lives for this rule. If null, falls back to the global {@link Config#bodyLocation}. */
        public BodyLocation bodyLocation = new BodyLocation();

        public ScopeRule() {}
        public ScopeRule(String matchKind, String pattern, String pipelineName) {
            this.matchKind = matchKind;
            this.pattern = pattern;
            this.pipelineName = pipelineName;
        }
    }

    /** Where in the HTTP message the ciphertext actually lives. */
    public static final class BodyLocation {
        /** "whole" (entire body), "header" (single header value), "regex" (group 1 over body). */
        public String kind = "whole";
        /** Interpretation depends on {@link #kind}. */
        public String expression = "";

        public BodyLocation() {}
        public BodyLocation(String kind, String expression) {
            this.kind = kind;
            this.expression = expression;
        }
    }

    /** Named key/IV/keypair in the Key Store. */
    public static final class NamedKey {
        public String name;
        /** "raw", "pem-public", "pem-private", "jwk". */
        public String kind = "raw";
        /** Encoding hint: "hex", "base64", "utf-8", "pem", "jwk-json". */
        public String encoding = "hex";
        public String material = "";       // encoded key bytes / PEM body
        public String notes = "";

        public NamedKey() {}
        public NamedKey(String name, String kind, String encoding, String material) {
            this.name = name;
            this.kind = kind;
            this.encoding = encoding;
            this.material = material;
        }
    }

    // ===================== top-level fields =====================
    public List<NamedPipeline> pipelines   = new ArrayList<>();
    public List<ScopeRule>     scopeRules  = new ArrayList<>();
    public List<NamedKey>      keys        = new ArrayList<>();

    // F3.5 toggles. Auto decrypt/encrypt is unconditional now — every in-scope
    // request and response is transformed for every supported tool — so there
    // is no master switch field. The per-tool toggles below remain because
    // they're occasionally useful (e.g. excluding Scanner from re-encryption
    // while it floods a target).
    public boolean applyToProxy      = true;
    public boolean applyToRepeater   = true;
    public boolean applyToIntruder   = true;
    public boolean applyToLogger     = true;
    public boolean applyToScanner    = false;
    public boolean applyToRequests   = true;
    public boolean applyToResponses  = true;

    // ===================== helpers =====================
    public NamedPipeline findPipeline(String name) {
        if (name == null || pipelines == null) return null;
        for (NamedPipeline p : pipelines) if (p != null && name.equals(p.name)) return p;
        return null;
    }

    public NamedKey findKey(String name) {
        if (name == null || keys == null) return null;
        for (NamedKey k : keys) if (k != null && name.equals(k.name)) return k;
        return null;
    }

    /** Deep-ish copy so mutation of the UI's working copy can't race handler threads.
     *  Also heals stale on-disk configs by re-initialising any missing nested fields. */
    public Config snapshot() {
        Config c = new Config();
        if (pipelines != null) for (NamedPipeline p : pipelines) {
            if (p == null) continue;
            NamedPipeline np = new NamedPipeline(p.name);
            if (p.steps != null) for (PipelineStep s : p.steps) {
                if (s == null) continue;
                PipelineStep ns = new PipelineStep(s.type);
                ns.enabled = s.enabled;
                ns.params = s.params == null ? new LinkedHashMap<>() : new LinkedHashMap<>(s.params);
                np.steps.add(ns);
            }
            c.pipelines.add(np);
        }
        if (scopeRules != null) for (ScopeRule r : scopeRules) {
            if (r == null) continue;
            ScopeRule nr = new ScopeRule(r.matchKind, r.pattern, r.pipelineName);
            nr.enabled = r.enabled;
            nr.bodyLocation = (r.bodyLocation != null)
                    ? new BodyLocation(r.bodyLocation.kind, r.bodyLocation.expression)
                    : new BodyLocation();
            c.scopeRules.add(nr);
        }
        if (keys != null) for (NamedKey k : keys) {
            if (k == null) continue;
            NamedKey nk = new NamedKey(k.name, k.kind, k.encoding, k.material);
            nk.notes = k.notes;
            c.keys.add(nk);
        }
        c.applyToProxy   = applyToProxy;
        c.applyToRepeater= applyToRepeater;
        c.applyToIntruder= applyToIntruder;
        c.applyToLogger  = applyToLogger;
        c.applyToScanner = applyToScanner;
        c.applyToRequests= applyToRequests;
        c.applyToResponses=applyToResponses;
        return c;
    }
}
