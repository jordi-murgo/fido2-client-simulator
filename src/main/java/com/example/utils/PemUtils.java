package com.example.utils;

import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.charset.StandardCharsets;

/**
 * Utility for encoding Java PublicKey to PEM format (X.509 SubjectPublicKeyInfo).
 */
public class PemUtils {
    /**
     * Encodes a Java PublicKey to PEM format (X.509 SubjectPublicKeyInfo).
     * @param publicKey The public key to encode
     * @return The PEM-encoded public key as a String
     */
    public static String publicKeyToPem(PublicKey publicKey) {
        StringBuilder sb = new StringBuilder();
        sb.append("-----BEGIN PUBLIC KEY-----\n");
        sb.append(EncodingUtils.base64Encode(publicKey.getEncoded()));
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
        byte[] encoded = EncodingUtils.base64Decode(pemClean);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        
        // Try EC first, then RSA
        try {
            KeyFactory kf = KeyFactory.getInstance("EC");
            return kf.generatePublic(keySpec);
        } catch (Exception e) {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(keySpec);
        }
    }

    /**
     * Loads a private key from a PEM file.
     * @param filePath The path to the PEM file containing the private key
     * @return The PrivateKey object
     * @throws Exception if the file cannot be read or the key cannot be parsed
     */
    public static PrivateKey loadPrivateKey(String filePath) throws Exception {
        String pemContent = new String(Files.readAllBytes(Paths.get(filePath)), StandardCharsets.UTF_8);
        return pemToPrivateKey(pemContent);
    }

    /**
     * Loads a public key from a PEM file.
     * @param filePath The path to the PEM file containing the public key
     * @return The PublicKey object
     * @throws Exception if the file cannot be read or the key cannot be parsed
     */
    public static PublicKey loadPublicKey(String filePath) throws Exception {
        String pemContent = new String(Files.readAllBytes(Paths.get(filePath)), StandardCharsets.UTF_8);
        return pemToPublicKey(pemContent);
    }

    /**
     * Decodes a PEM-encoded private key string to a Java PrivateKey.
     * @param pem The PEM-encoded private key
     * @return The Java PrivateKey
     * @throws Exception if the key cannot be parsed
     */
    public static PrivateKey pemToPrivateKey(String pem) throws Exception {
        String pemClean = pem.replaceAll("-----BEGIN PRIVATE KEY-----", "")
                             .replaceAll("-----END PRIVATE KEY-----", "")
                             .replaceAll("-----BEGIN EC PRIVATE KEY-----", "")
                             .replaceAll("-----END EC PRIVATE KEY-----", "")
                             .replaceAll("-----BEGIN RSA PRIVATE KEY-----", "")
                             .replaceAll("-----END RSA PRIVATE KEY-----", "")
                             .replaceAll("\\s", "");
        
        byte[] encoded = EncodingUtils.base64Decode(pemClean);
        
        // Try PKCS8 format first (most common)
        try {
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
            
            // Try EC first, then RSA
            try {
                KeyFactory kf = KeyFactory.getInstance("EC");
                return kf.generatePrivate(keySpec);
            } catch (Exception e) {
                KeyFactory kf = KeyFactory.getInstance("RSA");
                return kf.generatePrivate(keySpec);
            }
        } catch (Exception e) {
            throw new Exception("Unable to parse private key: " + e.getMessage(), e);
        }
    }

    /**
     * Encodes a Java PrivateKey to PEM format.
     * @param privateKey The private key to encode
     * @return The PEM-encoded private key as a String
     */
    public static String privateKeyToPem(PrivateKey privateKey) {
        StringBuilder sb = new StringBuilder();
        sb.append("-----BEGIN PRIVATE KEY-----\n");
        sb.append(EncodingUtils.base64Encode(privateKey.getEncoded()));
        sb.append("\n-----END PRIVATE KEY-----\n");
        return sb.toString();
    }
}
