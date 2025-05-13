package com.example.utils;

import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;

public class SignatureUtils {
    /**
     * Signs the given data using the provided private key.
     * @param data the data to sign
     * @param privateKey the private key to use for signing
     * @return the signature
     * @throws SignatureException if signing fails
     */
    public static byte[] sign(byte[] data, PrivateKey privateKey) throws SignatureException {
        try {
            String algorithm = privateKey.getAlgorithm();
            String signatureAlgorithm;
            if ("EC".equals(algorithm)) {
                signatureAlgorithm = "SHA256withECDSA";
            } else if ("RSA".equals(algorithm)) {
                signatureAlgorithm = "SHA256withRSA";
            } else {
                throw new IllegalArgumentException("Unsupported key algorithm: " + algorithm);
            }

            Signature signature = Signature.getInstance(signatureAlgorithm);
            signature.initSign(privateKey);
            signature.update(data);
            return signature.sign();
        } catch (Exception e) {
            throw new SignatureException("Failed to sign data: " + e.getMessage(), e);
        }
    }
}
