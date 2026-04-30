package com.cryptomobile.crypto;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;

import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;

/**
 * JWE step backed by Nimbus JOSE+JWT. Supported algorithm/enc combinations
 * are validated at construction time:
 * <ul>
 *   <li>{@code RSA-OAEP-256 + A256GCM}</li>
 *   <li>{@code dir + A256GCM}</li>
 *   <li>{@code ECDH-ES + A256GCM}</li>
 * </ul>
 * Other combinations Nimbus supports will also work — we simply pass the
 * configured values through.
 *
 * <p>Input to {@link #decrypt(byte[])} is the compact JWE serialization
 * ({@code eyJ...}); output of {@link #encrypt(byte[])} is the same.
 */
public final class JweStep implements CipherStep {

    private final JWEAlgorithm      alg;
    private final EncryptionMethod  enc;
    private final JWK               key;        // public for RSA/ECDH; symmetric for dir.
    private final JWK               privateKey; // for decryption (may be same as key for dir)

    public JweStep(JWEAlgorithm alg, EncryptionMethod enc, JWK key, JWK privateKey) {
        this.alg = alg;
        this.enc = enc;
        this.key = key;
        this.privateKey = privateKey;
    }

    public static JweStep fromParams(Map<String, String> params) throws CipherStepException {
        String algName = params.getOrDefault("alg", "RSA-OAEP-256");
        String encName = params.getOrDefault("enc", "A256GCM");
        JWEAlgorithm alg = JWEAlgorithm.parse(algName);
        EncryptionMethod enc = EncryptionMethod.parse(encName);

        String jwkPub = params.get("jwk-public");
        String jwkPrv = params.get("jwk-private");
        try {
            JWK pub = jwkPub == null || jwkPub.isBlank() ? null : JWK.parse(jwkPub);
            JWK prv = jwkPrv == null || jwkPrv.isBlank() ? null : JWK.parse(jwkPrv);
            if (pub == null && prv == null)
                throw new CipherStepException("JWE: at least one of jwk-public / jwk-private must be supplied");
            return new JweStep(alg, enc, pub, prv);
        } catch (java.text.ParseException pe) {
            throw new CipherStepException("JWE: invalid JWK JSON: " + pe.getMessage(), pe);
        }
    }

    @Override public String name() { return "JWE(" + alg + "+" + enc + ")"; }

    @Override
    public byte[] encrypt(byte[] input) throws CipherStepException {
        try {
            JWEHeader header = new JWEHeader.Builder(alg, enc).build();
            JWEObject object = new JWEObject(header, new Payload(input));
            JWEEncrypter enc = buildEncrypter();
            object.encrypt(enc);
            return object.serialize().getBytes(StandardCharsets.US_ASCII);
        } catch (Exception e) {
            throw new CipherStepException(name() + ": encryption failed: " + e.getMessage(), e);
        }
    }

    @Override
    public byte[] decrypt(byte[] input) throws CipherStepException {
        try {
            String compact = new String(input, StandardCharsets.US_ASCII).trim();
            JWEObject object = JWEObject.parse(compact);
            JWEDecrypter dec = buildDecrypter();
            object.decrypt(dec);
            return object.getPayload().toBytes();
        } catch (Exception e) {
            throw new CipherStepException(name() + ": decryption failed: " + e.getMessage(), e);
        }
    }

    private JWEEncrypter buildEncrypter() throws Exception {
        JWK k = key != null ? key : privateKey;
        if (k instanceof RSAKey rk) {
            RSAPublicKey pub = rk.toRSAPublicKey();
            return new RSAEncrypter(pub);
        }
        if (k instanceof OctetSequenceKey sk) {
            return new DirectEncrypter(sk);
        }
        if (k instanceof ECKey ek) {
            return new ECDHEncrypter(ek.toECPublicKey());
        }
        throw new CipherStepException(name() + ": unsupported JWK type " + k.getKeyType());
    }

    private JWEDecrypter buildDecrypter() throws Exception {
        JWK k = privateKey != null ? privateKey : key;
        if (k instanceof RSAKey rk) {
            RSAPrivateKey prv = rk.toRSAPrivateKey();
            if (prv == null) throw new CipherStepException(name() + ": JWK is RSA but has no private component");
            return new RSADecrypter(prv);
        }
        if (k instanceof OctetSequenceKey sk) {
            return new DirectDecrypter(sk);
        }
        if (k instanceof ECKey ek) {
            if (ek.toECPrivateKey() == null) throw new CipherStepException(name() + ": EC JWK has no private component");
            return new ECDHDecrypter(ek);
        }
        throw new CipherStepException(name() + ": unsupported JWK type " + k.getKeyType());
    }
}
