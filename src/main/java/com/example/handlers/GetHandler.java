package com.example;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.util.List;
import java.util.Optional;
import java.util.Scanner;

import com.example.utils.EncodingUtils;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.yubico.webauthn.data.AuthenticatorAssertionResponse;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions;
import com.yubico.webauthn.data.UserVerificationRequirement;

/**
 * Handles the FIDO2 authentication (get) operation, simulating an authenticator's credential usage.
 */
public class GetHandler extends BaseHandler {
    private boolean interactive;
    /**
     * Constructs a GetHandler.
     * @param keyStoreManager The KeyStoreManager instance
     * @param jsonMapper The Jackson ObjectMapper
     * @param interactive Whether to enable interactive credential selection
     */
    public GetHandler(KeyStoreManager keyStoreManager, ObjectMapper jsonMapper, boolean interactive) {
        super(keyStoreManager, jsonMapper);
        this.interactive = interactive;
    }

    /**
     * Handles the authentication of a FIDO2 credential, returning the PublicKeyCredential as JSON.
     * @param optionsJson JSON string for PublicKeyCredentialRequestOptions
     * @return JSON string representing the PublicKeyCredential
     * @throws Exception on error
     */
    public String handleGet(String optionsJson) throws Exception {
        try {
            // Decode and ensure extensions are present
            optionsJson = tryDecodeBase64Json(optionsJson);
            optionsJson = ensureExtensionsInJson(optionsJson);
            
            // Parse options
            PublicKeyCredentialRequestOptions options = jsonMapper.readValue(optionsJson, PublicKeyCredentialRequestOptions.class);
            options = ensureExtensions(options);
    
            // 1. Select a credential
            ByteArray credentialId = selectCredential(options);
            
            // 2. Get private key from keystore
            PrivateKey privateKey = keyStoreManager.getPrivateKey(credentialId);
            if (privateKey == null) {
                throw new IllegalStateException("No private key found for credential: " + credentialId.getBase64Url());
            }
            
            // 3. Create authenticator data
            byte[] authenticatorData = createAuthenticatorData(options, credentialId);
            
            // 4. Create client data JSON
            String clientDataJson = createClientDataJson(options);
            
            // 5. Generate signature
            byte[] signature = generateSignature(authenticatorData, clientDataJson, privateKey);
            
            // 6. Create assertion response
            AuthenticatorAssertionResponse response = createAssertionResponse(authenticatorData, clientDataJson, signature);
            
            // 7. Create credential
            PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> credential = createCredential(credentialId, response);
            
            // 8. Convert to JSON and add rawId
            String assertionResponseJson = jsonMapper.writerWithDefaultPrettyPrinter().writeValueAsString(credential);
            return addRawIdToResponse(assertionResponseJson);
        } catch (IOException | SignatureException e) {
            throw new Exception("Error during authentication: " + e.getMessage(), e);
        }
    }

    private ByteArray selectCredential(PublicKeyCredentialRequestOptions options) {
        Optional<List<PublicKeyCredentialDescriptor>> allowedCredentialsOpt = options.getAllowCredentials();
        List<PublicKeyCredentialDescriptor> allowedCredentials = allowedCredentialsOpt.orElse(List.of());
        List<ByteArray> availableCredentialIds = keyStoreManager.getCredentialIdsForRpId(options.getRpId());
        
        List<ByteArray> matchingCredentialIds = availableCredentialIds.stream()
            .filter(id -> allowedCredentials.isEmpty() || 
                   allowedCredentials.stream().anyMatch(cred -> cred.getId().equals(id)))
            .toList();
        
        if (matchingCredentialIds.isEmpty()) {
            throw new IllegalStateException("No matching credentials found");
        }
        
        if (matchingCredentialIds.size() == 1) {
            return matchingCredentialIds.get(0);
        }
        
        // If we have multiple credentials but not in interactive mode, just return the first one
        if (!interactive) {
            System.out.println("Multiple credentials found, automatically selecting the first one (non-interactive mode)");
            return matchingCredentialIds.get(0);
        }
        
        return promptForCredentialSelection(matchingCredentialIds);
    }

    private ByteArray promptForCredentialSelection(List<ByteArray> credentialIds) {
        // Display available credentials
        System.out.println("\nMultiple credentials found. Please select one:");
        for (int i = 0; i < credentialIds.size(); i++) {
            System.out.printf("%d. %s%n", i + 1, credentialIds.get(i).getBase64Url());
        }
        
        try {
            System.out.print("Enter your choice (1-" + credentialIds.size() + "): ");
            Scanner scanner = new Scanner(System.in);
            
            // Check if input is available without blocking (for scripts)
            if (System.in.available() > 0) {
                int choice = scanner.nextInt();
                if (choice >= 1 && choice <= credentialIds.size()) {
                    return credentialIds.get(choice - 1);
                }
            } else {
                // If running non-interactively or can't read input, select the first credential
                System.out.println("No input available, automatically selecting first credential.");
                return credentialIds.get(0);
            }
        } catch (Exception e) {
            // If any error occurs (including IO exceptions or format errors), select the first credential
            System.out.println("Error during selection, automatically selecting first credential: " + e.getMessage());
            return credentialIds.get(0);
        }
        
        // Default to first credential
        return credentialIds.get(0);
    }

    private byte[] createAuthenticatorData(PublicKeyCredentialRequestOptions options, ByteArray credentialId) {
        byte[] rpIdHash = EncodingUtils.sha256(options.getRpId().getBytes(java.nio.charset.StandardCharsets.UTF_8));
        byte flags = (byte) 0x01; // UP flag
        if (options.getUserVerification().orElse(UserVerificationRequirement.DISCOURAGED) == UserVerificationRequirement.REQUIRED) {
            flags |= (byte) 0x04; // UV flag
        }
        long signCount = keyStoreManager.getSignCount(credentialId);
        
        return composeAuthenticatorData(rpIdHash, flags, signCount);
    }

    private String createClientDataJson(PublicKeyCredentialRequestOptions options) throws JsonProcessingException {
        ObjectNode clientData = jsonMapper.createObjectNode();
        clientData.put("type", "webauthn.get");
        clientData.put("challenge", options.getChallenge().getBase64Url());
        clientData.put("origin", "https://" + options.getRpId());
        return jsonMapper.writeValueAsString(clientData);
    }

    private byte[] generateSignature(byte[] authenticatorData, String clientDataJson, PrivateKey privateKey) throws SignatureException {
        byte[] clientDataHash = EncodingUtils.sha256(clientDataJson.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        byte[] dataToSign = ByteBuffer.allocate(authenticatorData.length + clientDataHash.length)
            .put(authenticatorData)
            .put(clientDataHash)
            .array();
        
        return EncodingUtils.sign(dataToSign, privateKey);
    }

    /**
     * Creates an AuthenticatorAssertionResponse from authenticator data, client data JSON, and signature.
     * @param authenticatorData The authenticator data bytes
     * @param clientDataJson The client data JSON string
     * @param signature The signature bytes
     * @return The assertion response
     */
    private AuthenticatorAssertionResponse createAssertionResponse(byte[] authenticatorData, String clientDataJson, byte[] signature) {
        try {
            // Convert raw bytes directly - no intermediate conversions
            ByteArray authenticatorDataByteArray = new ByteArray(authenticatorData);
            
            // For client data JSON, ensure proper encoding
            byte[] clientDataJsonBytes = clientDataJson.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            ByteArray clientDataJsonByteArray = new ByteArray(clientDataJsonBytes);
            
            // Signature as ByteArray
            ByteArray signatureByteArray = new ByteArray(signature);
            
            return AuthenticatorAssertionResponse.builder()
                .authenticatorData(authenticatorDataByteArray)
                .clientDataJSON(clientDataJsonByteArray)
                .signature(signatureByteArray)
                .build();
        } catch (Exception e) {
            throw new IllegalArgumentException("Error creating assertion response: " + e.getMessage(), e);
        }
    }

    private PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> createCredential(
            ByteArray credentialId, AuthenticatorAssertionResponse response) {
        return PublicKeyCredential.<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs>builder()
            .id(credentialId)
            .response(response)
            .clientExtensionResults(ClientAssertionExtensionOutputs.builder().build())
            .build();
    }

    private static byte[] composeAuthenticatorData(byte[] rpIdHash, byte flags, long signCount) {
        byte[] signCountBytes = ByteBuffer.allocate(4).putInt((int) signCount).array();
        
        byte[] out = new byte[37];
        System.arraycopy(rpIdHash, 0, out, 0, 32);
        out[32] = flags;
        System.arraycopy(signCountBytes, 0, out, 33, 4);
        
        return out;
    }
}
