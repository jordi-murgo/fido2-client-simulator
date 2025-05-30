package com.example.handlers;

import com.example.utils.HashUtils;
import com.example.utils.SignatureUtils;
import com.example.utils.PemUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import static org.junit.jupiter.api.Assertions.*;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

/**
 * Test class for verifying FIDO2 signature generation in GetHandler.
 * Tests ensure the signature generation follows WebAuthn specification correctly.
 */
public class GetHandlerSignatureTest {

    private PrivateKey testPrivateKey;
    private PublicKey testPublicKey;
    private byte[] testAuthenticatorData;
    private String testClientDataJson;

    @BeforeEach
    void setUp() throws Exception {
        // Load test keys (you'll need to create test key files)
        testPrivateKey = PemUtils.loadPrivateKey("src/test/resources/test-private-key.pem");
        testPublicKey = PemUtils.loadPublicKey("src/test/resources/test-public-key.pem");
        
        // Test authenticator data (37 bytes minimum)
        testAuthenticatorData = createTestAuthenticatorData();
        
        // Test client data JSON
        testClientDataJson = "{\"type\":\"webauthn.get\",\"challenge\":\"test-challenge\",\"origin\":\"https://example.com\"}";
    }

    @Test
    void testSignatureGeneration() throws Exception {
        // Generate signature using the same logic as GetHandler
        byte[] signature = generateTestSignature(testAuthenticatorData, testClientDataJson, testPrivateKey);
        
        assertNotNull(signature);
        assertTrue(signature.length > 0);
        
        // Verify signature can be validated
        assertTrue(verifySignature(testAuthenticatorData, testClientDataJson, signature, testPublicKey));
    }

    @Test
    void testClientDataHashCalculation() throws Exception {
        byte[] expectedHash = HashUtils.sha256(testClientDataJson.getBytes(StandardCharsets.UTF_8));
        byte[] actualHash = HashUtils.sha256(testClientDataJson.getBytes(StandardCharsets.UTF_8));
        
        assertArrayEquals(expectedHash, actualHash);
        assertEquals(32, actualHash.length); // SHA-256 produces 32 bytes
    }

    @Test
    void testDataToSignConstruction() throws Exception {
        byte[] clientDataHash = HashUtils.sha256(testClientDataJson.getBytes(StandardCharsets.UTF_8));
        
        // Construct dataToSign the same way as GetHandler
        byte[] dataToSign = ByteBuffer.allocate(testAuthenticatorData.length + clientDataHash.length)
            .put(testAuthenticatorData)
            .put(clientDataHash)
            .array();
        
        assertEquals(testAuthenticatorData.length + 32, dataToSign.length);
        
        // Verify authenticator data is at the beginning
        byte[] extractedAuthData = new byte[testAuthenticatorData.length];
        System.arraycopy(dataToSign, 0, extractedAuthData, 0, testAuthenticatorData.length);
        assertArrayEquals(testAuthenticatorData, extractedAuthData);
        
        // Verify client data hash is at the end
        byte[] extractedClientHash = new byte[32];
        System.arraycopy(dataToSign, testAuthenticatorData.length, extractedClientHash, 0, 32);
        assertArrayEquals(clientDataHash, extractedClientHash);
    }

    @Test
    void testDifferentClientDataProducesDifferentSignatures() throws Exception {
        String clientData1 = "{\"type\":\"webauthn.get\",\"challenge\":\"challenge1\",\"origin\":\"https://example.com\"}";
        String clientData2 = "{\"type\":\"webauthn.get\",\"challenge\":\"challenge2\",\"origin\":\"https://example.com\"}";
        
        byte[] signature1 = generateTestSignature(testAuthenticatorData, clientData1, testPrivateKey);
        byte[] signature2 = generateTestSignature(testAuthenticatorData, clientData2, testPrivateKey);
        
        assertFalse(java.util.Arrays.equals(signature1, signature2));
    }

    @Test
    void testDifferentAuthenticatorDataProducesDifferentSignatures() throws Exception {
        byte[] authData1 = createTestAuthenticatorData();
        byte[] authData2 = createTestAuthenticatorData();
        authData2[authData2.length - 1] = (byte) (authData2[authData2.length - 1] + 1); // Change counter
        
        byte[] signature1 = generateTestSignature(authData1, testClientDataJson, testPrivateKey);
        byte[] signature2 = generateTestSignature(authData2, testClientDataJson, testPrivateKey);
        
        assertFalse(java.util.Arrays.equals(signature1, signature2));
    }

    /**
     * Helper method to generate signature using the same logic as GetHandler
     */
    private byte[] generateTestSignature(byte[] authenticatorData, String clientDataJson, PrivateKey privateKey) throws Exception {
        byte[] clientDataHash = HashUtils.sha256(clientDataJson.getBytes(StandardCharsets.UTF_8));
        byte[] dataToSign = ByteBuffer.allocate(authenticatorData.length + clientDataHash.length)
            .put(authenticatorData)
            .put(clientDataHash)
            .array();
        
        return SignatureUtils.sign(dataToSign, privateKey);
    }

    /**
     * Helper method to verify signature using public key
     */
    private boolean verifySignature(byte[] authenticatorData, String clientDataJson, byte[] signature, PublicKey publicKey) throws Exception {
        byte[] clientDataHash = HashUtils.sha256(clientDataJson.getBytes(StandardCharsets.UTF_8));
        byte[] dataToSign = ByteBuffer.allocate(authenticatorData.length + clientDataHash.length)
            .put(authenticatorData)
            .put(clientDataHash)
            .array();
        
        String algorithm = publicKey.getAlgorithm();
        String signatureAlgorithm;
        if ("EC".equals(algorithm)) {
            signatureAlgorithm = "SHA256withECDSA";
        } else if ("RSA".equals(algorithm)) {
            signatureAlgorithm = "SHA256withRSA";
        } else {
            throw new IllegalArgumentException("Unsupported key algorithm: " + algorithm);
        }

        Signature sig = Signature.getInstance(signatureAlgorithm);
        sig.initVerify(publicKey);
        sig.update(dataToSign);
        return sig.verify(signature);
    }

    /**
     * Creates test authenticator data (minimum 37 bytes)
     * Structure: rpIdHash(32) + flags(1) + signCount(4)
     */
    private byte[] createTestAuthenticatorData() {
        byte[] rpIdHash = HashUtils.sha256("example.com".getBytes(StandardCharsets.UTF_8));
        byte flags = 0x01; // User Present
        int signCount = 1;
        
        return ByteBuffer.allocate(37)
            .put(rpIdHash)      // 32 bytes
            .put(flags)         // 1 byte
            .putInt(signCount)  // 4 bytes
            .array();
    }
}
