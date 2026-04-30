package com.cryptomobile.crypto;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

class JweStepTest {

    @Test
    void rsa_oaep_256_a256gcm_round_trip() throws Exception {
        RSAKey rsa = new RSAKeyGenerator(2048).keyUse(KeyUse.ENCRYPTION).generate();
        JweStep step = new JweStep(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM,
                rsa.toPublicJWK(), rsa);
        byte[] plain = "hello JWE".getBytes();
        byte[] ct = step.encrypt(plain);
        assertArrayEquals(plain, step.decrypt(ct));
    }

    @Test
    void dir_a256gcm_round_trip() throws Exception {
        OctetSequenceKey key = new OctetSequenceKeyGenerator(256).generate();
        JweStep step = new JweStep(JWEAlgorithm.DIR, EncryptionMethod.A256GCM, key, key);
        byte[] plain = "direct AES-GCM".getBytes();
        byte[] ct = step.encrypt(plain);
        assertArrayEquals(plain, step.decrypt(ct));
    }

    @Test
    void ecdh_es_a256gcm_round_trip() throws Exception {
        ECKey ec = new ECKeyGenerator(Curve.P_256).keyUse(KeyUse.ENCRYPTION).generate();
        JweStep step = new JweStep(JWEAlgorithm.ECDH_ES, EncryptionMethod.A256GCM, ec.toPublicJWK(), ec);
        byte[] plain = "ECDH-ES key agreement".getBytes();
        byte[] ct = step.encrypt(plain);
        assertArrayEquals(plain, step.decrypt(ct));
    }
}
