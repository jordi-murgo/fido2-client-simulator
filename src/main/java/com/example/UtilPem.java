package com.example;

import java.security.PublicKey;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Utility for encoding Java PublicKey to PEM format (X.509 SubjectPublicKeyInfo).
 */
public class UtilPem {
    /**
     * Encodes a Java PublicKey to PEM format (X.509 SubjectPublicKeyInfo).
     * @param publicKey The public key to encode
     * @return The PEM-encoded public key as a String
     */
    public static String publicKeyToPem(PublicKey publicKey) {
        StringBuilder sb = new StringBuilder();
        sb.append("-----BEGIN PUBLIC KEY-----\n");
        sb.append(Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(publicKey.getEncoded()));
        sb.append("\n-----END PUBLIC KEY-----\n");
        return sb.toString();
    }
    
    /**
     * Decodes a PEM-encoded public key string to a Java PublicKey.
     * @param pem The PEM-encoded public key
     * @return The Java PublicKey
     */
    public static PublicKey pemToPublicKey(String pem) throws Exception {
        String pemClean = pem.replaceAll("-----BEGIN PUBLIC KEY-----", "")
                             .replaceAll("-----END PUBLIC KEY-----", "")
                             .replaceAll("\\s", "");
        byte[] encoded = Base64.getDecoder().decode(pemClean);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        return KeyFactory.getInstance("EC").generatePublic(keySpec); // or "RSA" if using RSA
    }
}
