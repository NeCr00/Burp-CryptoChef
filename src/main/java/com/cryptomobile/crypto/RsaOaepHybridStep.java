package com.cryptomobile.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.MGF1ParameterSpec;
import java.util.Arrays;
import java.util.Map;

/**
 * RSA-OAEP wrapped AES key + AES body ("hybrid" construction).
 *
 * <p>Wire format (encrypt direction):
 * <pre>
 *   [ 2 bytes: wrapped-key-length N ][ N bytes: RSA-OAEP wrap of AES key ]
 *   [ 12 or 16 bytes: nonce/IV ][ ciphertext + tag ]
 * </pre>
 *
 * <p>Inner cipher is {@code AES-GCM} by default; set param
 * {@code inner=aes-cbc} for CBC (PKCS#7) instead.
 *
 * <p>The 2-byte length prefix is big-endian — this is a common mobile-app
 * pattern, not standardized, so the exact layout may differ in your target.
 * Adjust this class if your target uses a different framing.
 */
public final class RsaOaepHybridStep implements CipherStep {

    public enum Inner { AES_GCM, AES_CBC }

    private static final SecureRandom RNG = new SecureRandom();

    private final PublicKey  publicKey;   // nullable: needed for encrypt
    private final PrivateKey privateKey;  // nullable: needed for decrypt
    private final String     oaepHash;    // "SHA-1" or "SHA-256"
    private final String     mgfHash;     // same space
    private final int        aesKeyLen;   // 16, 24, or 32
    private final Inner      inner;

    public RsaOaepHybridStep(PublicKey  publicKey,
                             PrivateKey privateKey,
                             String     oaepHash,
                             String     mgfHash,
                             int        aesKeyLen,
                             Inner      inner) {
        this.publicKey  = publicKey;
        this.privateKey = privateKey;
        this.oaepHash   = oaepHash;
        this.mgfHash    = mgfHash;
        this.aesKeyLen  = aesKeyLen;
        this.inner      = inner;
    }

    public static RsaOaepHybridStep fromParams(Map<String, String> params) throws CipherStepException {
        String pubPem = params.get("public-key-pem");
        String prvPem = params.get("private-key-pem");
        PublicKey  pub = (pubPem == null || pubPem.isBlank()) ? null : KeyMaterialCodec.parsePublicKey(pubPem, "RSA");
        PrivateKey prv = (prvPem == null || prvPem.isBlank()) ? null : KeyMaterialCodec.parsePrivateKey(prvPem, "RSA");
        String oaep = params.getOrDefault("oaep-hash", "SHA-256");
        String mgf  = params.getOrDefault("mgf-hash",  oaep);
        int aesLen  = Integer.parseInt(params.getOrDefault("aes-bits", "256")) / 8;
        Inner inner = "aes-cbc".equalsIgnoreCase(params.getOrDefault("inner", "aes-gcm"))
                ? Inner.AES_CBC : Inner.AES_GCM;
        return new RsaOaepHybridStep(pub, prv, oaep, mgf, aesLen, inner);
    }

    @Override public String name() { return "RSA-OAEP-" + oaepHash + "-hybrid(" + (inner == Inner.AES_GCM ? "GCM" : "CBC") + ")"; }

    private OAEPParameterSpec oaepSpec() {
        return new OAEPParameterSpec(oaepHash, "MGF1", new MGF1ParameterSpec(mgfHash), PSource.PSpecified.DEFAULT);
    }

    @Override
    public byte[] encrypt(byte[] input) throws CipherStepException {
        if (publicKey == null) throw new CipherStepException(name() + ": no RSA public key configured");
        try {
            // 1) fresh AES key
            byte[] aesKey = new byte[aesKeyLen];
            RNG.nextBytes(aesKey);

            // 2) wrap it
            Cipher wrap = Cipher.getInstance("RSA/ECB/OAEPPadding");
            wrap.init(Cipher.ENCRYPT_MODE, publicKey, oaepSpec());
            byte[] wrapped = wrap.doFinal(aesKey);
            if (wrapped.length > 0xFFFF)
                throw new CipherStepException(name() + ": wrapped key too large for 2-byte length prefix");

            // 3) encrypt body
            byte[] iv;
            byte[] body;
            if (inner == Inner.AES_GCM) {
                iv = new byte[12];
                RNG.nextBytes(iv);
                Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
                c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aesKey, "AES"), new GCMParameterSpec(128, iv));
                body = c.doFinal(input);
            } else {
                iv = new byte[16];
                RNG.nextBytes(iv);
                Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
                c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aesKey, "AES"), new IvParameterSpec(iv));
                body = c.doFinal(input);
            }

            byte[] out = new byte[2 + wrapped.length + iv.length + body.length];
            out[0] = (byte) ((wrapped.length >> 8) & 0xFF);
            out[1] = (byte) (wrapped.length & 0xFF);
            System.arraycopy(wrapped, 0, out, 2, wrapped.length);
            System.arraycopy(iv, 0, out, 2 + wrapped.length, iv.length);
            System.arraycopy(body, 0, out, 2 + wrapped.length + iv.length, body.length);
            return out;
        } catch (Exception e) {
            throw new CipherStepException(name() + ": encryption failed: " + e.getMessage(), e);
        }
    }

    @Override
    public byte[] decrypt(byte[] input) throws CipherStepException {
        if (privateKey == null) throw new CipherStepException(name() + ": no RSA private key configured");
        try {
            if (input.length < 2) throw new CipherStepException(name() + ": input too short");
            int wlen = ((input[0] & 0xFF) << 8) | (input[1] & 0xFF);
            int ivLen = inner == Inner.AES_GCM ? 12 : 16;
            if (input.length < 2 + wlen + ivLen)
                throw new CipherStepException(name() + ": input too short for wrapped-key+IV");
            byte[] wrapped = Arrays.copyOfRange(input, 2, 2 + wlen);
            byte[] iv      = Arrays.copyOfRange(input, 2 + wlen, 2 + wlen + ivLen);
            byte[] body    = Arrays.copyOfRange(input, 2 + wlen + ivLen, input.length);

            Cipher unwrap = Cipher.getInstance("RSA/ECB/OAEPPadding");
            unwrap.init(Cipher.DECRYPT_MODE, privateKey, oaepSpec());
            byte[] aesKey = unwrap.doFinal(wrapped);

            if (inner == Inner.AES_GCM) {
                Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
                c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aesKey, "AES"), new GCMParameterSpec(128, iv));
                return c.doFinal(body);
            } else {
                Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
                c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aesKey, "AES"), new IvParameterSpec(iv));
                return c.doFinal(body);
            }
        } catch (Exception e) {
            throw new CipherStepException(name() + ": decryption failed: " + e.getMessage(), e);
        }
    }
}
