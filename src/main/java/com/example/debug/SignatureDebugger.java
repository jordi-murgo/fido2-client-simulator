package com.example.debug;

import com.example.utils.HashUtils;
import com.example.utils.SignatureUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

/**
 * Debug utility for FIDO2 signature generation verification.
 * Provides detailed logging and validation of the signature process.
 */
public class SignatureDebugger {
    
    private static final Logger log = LoggerFactory.getLogger(SignatureDebugger.class);

    /**
     * Converts byte array to hexadecimal string representation
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }

    /**
     * Generates a signature with detailed debug logging
     */
    public static byte[] debugGenerateSignature(byte[] authenticatorData, String clientDataJson, PrivateKey privateKey) throws Exception {
        log.info("=== SIGNATURE GENERATION DEBUG ===");
        
        // 1. Log authenticator data
        log.info("Authenticator Data Length: {} bytes", authenticatorData.length);
        log.debug("Authenticator Data (hex): {}", bytesToHex(authenticatorData));
        
        if (authenticatorData.length >= 37) {
            byte[] rpIdHash = new byte[32];
            System.arraycopy(authenticatorData, 0, rpIdHash, 0, 32);
            log.info("RP ID Hash: {}", bytesToHex(rpIdHash));
            
            byte flags = authenticatorData[32];
            log.info("Flags: 0x{} (binary: {})", String.format("%02X", flags), String.format("%8s", Integer.toBinaryString(flags & 0xFF)).replace(' ', '0'));
            log.info("  - User Present (UP): {}", (flags & 0x01) != 0);
            log.info("  - User Verified (UV): {}", (flags & 0x04) != 0);
            log.info("  - Attested Credential Data (AT): {}", (flags & 0x40) != 0);
            log.info("  - Extension Data (ED): {}", (flags & 0x80) != 0);
            
            if (authenticatorData.length >= 37) {
                int signCount = ByteBuffer.wrap(authenticatorData, 33, 4).getInt();
                log.info("Sign Count: {}", signCount);
            }
        }
        
        // 2. Log client data
        log.info("Client Data JSON: {}", clientDataJson);
        log.info("Client Data JSON Length: {} bytes", clientDataJson.getBytes(StandardCharsets.UTF_8).length);
        
        // 3. Calculate and log client data hash
        byte[] clientDataHash = HashUtils.sha256(clientDataJson.getBytes(StandardCharsets.UTF_8));
        log.info("Client Data Hash: {}", bytesToHex(clientDataHash));
        log.info("Client Data Hash Length: {} bytes", clientDataHash.length);
        
        // 4. Construct data to sign
        byte[] dataToSign = ByteBuffer.allocate(authenticatorData.length + clientDataHash.length)
            .put(authenticatorData)
            .put(clientDataHash)
            .array();
        
        log.info("Data To Sign Length: {} bytes (AuthData: {} + ClientDataHash: {})", 
                dataToSign.length, authenticatorData.length, clientDataHash.length);
        log.debug("Data To Sign (hex): {}", bytesToHex(dataToSign));
        
        // 5. Generate signature
        log.info("Private Key Algorithm: {}", privateKey.getAlgorithm());
        log.info("Private Key Format: {}", privateKey.getFormat());
        
        byte[] signature = SignatureUtils.sign(dataToSign, privateKey);
        log.info("Generated Signature Length: {} bytes", signature.length);
        log.debug("Generated Signature (hex): {}", bytesToHex(signature));
        
        log.info("=== SIGNATURE GENERATION COMPLETE ===");
        
        return signature;
    }

    /**
     * Verifies a signature with detailed debug logging
     */
    public static boolean debugVerifySignature(byte[] authenticatorData, String clientDataJson, 
                                             byte[] signature, PublicKey publicKey) throws Exception {
        log.info("=== SIGNATURE VERIFICATION DEBUG ===");
        
        // Reconstruct data to verify
        byte[] clientDataHash = HashUtils.sha256(clientDataJson.getBytes(StandardCharsets.UTF_8));
        byte[] dataToVerify = ByteBuffer.allocate(authenticatorData.length + clientDataHash.length)
            .put(authenticatorData)
            .put(clientDataHash)
            .array();
        
        log.info("Verifying with Public Key Algorithm: {}", publicKey.getAlgorithm());
        log.info("Signature to verify length: {} bytes", signature.length);
        log.debug("Signature to verify (hex): {}", bytesToHex(signature));
        
        // Determine signature algorithm
        String algorithm = publicKey.getAlgorithm();
        String signatureAlgorithm;
        if ("EC".equals(algorithm)) {
            signatureAlgorithm = "SHA256withECDSA";
        } else if ("RSA".equals(algorithm)) {
            signatureAlgorithm = "SHA256withRSA";
        } else {
            throw new IllegalArgumentException("Unsupported key algorithm: " + algorithm);
        }
        
        log.info("Using signature algorithm: {}", signatureAlgorithm);
        
        // Verify signature
        Signature sig = Signature.getInstance(signatureAlgorithm);
        sig.initVerify(publicKey);
        sig.update(dataToVerify);
        boolean isValid = sig.verify(signature);
        
        log.info("Signature verification result: {}", isValid ? "VALID" : "INVALID");
        log.info("=== SIGNATURE VERIFICATION COMPLETE ===");
        
        return isValid;
    }

    /**
     * Compares two signature generation processes to identify differences
     */
    public static void compareSignatureGenerations(byte[] authData1, String clientData1,
                                                  byte[] authData2, String clientData2,
                                                  PrivateKey privateKey) throws Exception {
        log.info("=== SIGNATURE COMPARISON DEBUG ===");
        
        log.info("Comparing two signature generation processes...");
        
        // Generate both signatures
        byte[] sig1 = debugGenerateSignature(authData1, clientData1, privateKey);
        byte[] sig2 = debugGenerateSignature(authData2, clientData2, privateKey);
        
        // Compare results
        boolean signaturesEqual = java.util.Arrays.equals(sig1, sig2);
        boolean authDataEqual = java.util.Arrays.equals(authData1, authData2);
        boolean clientDataEqual = clientData1.equals(clientData2);
        
        log.info("Authenticator Data Equal: {}", authDataEqual);
        log.info("Client Data Equal: {}", clientDataEqual);
        log.info("Signatures Equal: {}", signaturesEqual);
        
        if (!authDataEqual) {
            log.info("Authenticator Data differences found");
            if (authData1.length != authData2.length) {
                log.info("  - Length difference: {} vs {}", authData1.length, authData2.length);
            } else {
                for (int i = 0; i < authData1.length; i++) {
                    if (authData1[i] != authData2[i]) {
                        log.info("  - Byte difference at position {}: 0x{} vs 0x{}", 
                                i, String.format("%02X", authData1[i]), String.format("%02X", authData2[i]));
                    }
                }
            }
        }
        
        if (!clientDataEqual) {
            log.info("Client Data differences found");
            log.info("  - ClientData1: {}", clientData1);
            log.info("  - ClientData2: {}", clientData2);
        }
        
        log.info("=== SIGNATURE COMPARISON COMPLETE ===");
    }
}
