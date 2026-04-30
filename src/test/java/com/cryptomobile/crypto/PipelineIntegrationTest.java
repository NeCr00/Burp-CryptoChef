package com.cryptomobile.crypto;

import com.cryptomobile.config.Config;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

/** Integration test: multilayer Base64 -> AES-256-CBC -> Base64. */
class PipelineIntegrationTest {

    @Test
    void multilayer_base64_aes_base64() throws Exception {
        Config cfg = new Config();
        Config.NamedKey k = new Config.NamedKey(
                "test-key", "raw", "hex",
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        cfg.keys.add(k);

        Config.NamedPipeline p = new Config.NamedPipeline("multilayer");
        // Step 1: BASE64 decode (i.e. strip wire-level outer base64 on decrypt;
        //                       add outer base64 on encrypt).
        Config.PipelineStep s1 = new Config.PipelineStep("BASE64");
        s1.params.put("variant", "standard");
        s1.params.put("padding", "true");
        p.steps.add(s1);

        // Step 2: AES-256-CBC with random prepended IV
        Config.PipelineStep s2 = new Config.PipelineStep("AES-256-CBC");
        s2.params.put("key-ref", "test-key");
        s2.params.put("iv-mode", "random");
        p.steps.add(s2);

        // Step 3: BASE64 again (inner layer often used to make JSON embeddable)
        Config.PipelineStep s3 = new Config.PipelineStep("BASE64");
        s3.params.put("variant", "url-safe");
        s3.params.put("padding", "false");
        p.steps.add(s3);

        cfg.pipelines.add(p);

        Pipeline pipe = Pipeline.fromConfig(p, cfg);
        byte[] plain = "This is a test of a three-stage pipeline.".getBytes();
        byte[] cipher = pipe.encrypt(plain);
        byte[] back   = pipe.decrypt(cipher);
        assertArrayEquals(plain, back);
    }

    @Test
    void trace_gives_one_stage_per_step() throws Exception {
        Config cfg = new Config();
        Config.NamedPipeline np = new Config.NamedPipeline("x");
        Config.PipelineStep b64 = new Config.PipelineStep("BASE64");
        b64.params.put("variant", "standard");
        np.steps.add(b64);
        np.steps.add(b64);   // twice for fun
        cfg.pipelines.add(np);

        Pipeline pipe = Pipeline.fromConfig(np, cfg);
        List<Pipeline.Stage> stages = pipe.encryptWithTrace("hi".getBytes());
        assertArrayEquals(new int[]{stages.size()}, new int[]{2});
    }
}
