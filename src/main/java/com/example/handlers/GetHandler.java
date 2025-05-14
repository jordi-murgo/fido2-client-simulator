package com.example.handlers;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import com.example.storage.CredentialMetadata;
import com.example.storage.CredentialStore;
import com.example.utils.HashUtils;
import com.example.utils.SignatureUtils;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.yubico.webauthn.data.AuthenticatorAssertionResponse;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions;

/**
 * Handles the FIDO2 authentication (get) operation, simulating an authenticator's credential usage.
 */
public class GetHandler extends BaseHandler implements CommandHandler {
    @Override
    public String handleRequest(String requestJson) throws Exception {
        return handleGet(requestJson);
    }
    private boolean interactive;
    /**
     * Constructs a GetHandler.
     * @param credentialStore The CredentialStore instance
     * @param jsonMapper The Jackson ObjectMapper
     * @param interactive Whether to enable interactive credential selection
     */
    public GetHandler(CredentialStore credentialStore, ObjectMapper jsonMapper, boolean interactive) {
        super(credentialStore, jsonMapper);
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
            PrivateKey privateKey = credentialStore.getPrivateKey(credentialId)
                .orElseThrow(() -> new IllegalArgumentException("No private key found for credential ID: " + credentialId.getBase64Url()));
            
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
        List<ByteArray> availableCredentialIds = credentialStore.getCredentialIdsForRpId(options.getRpId());
        
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
        Map<String, CredentialMetadata> metadataMap = credentialStore.getMetadataMap();
        
        System.out.println("\nAvailable credentials:");
        // Print header row for the table
        System.out.println("-----------------------------------------------------------------------------------------");
        System.out.println("  IDX | CREDENTIAL ID          | CREATION TIMESTAMP  | CNT | USER INFO");
        System.out.println("-----------------------------------------------------------------------------------------");
        
        for (int i = 0; i < credentialIds.size(); i++) {
            String credId = credentialIds.get(i).getBase64Url();
            // Get user info from metadata
            String userInfo = "Unknown user";
            String createdAt = "N/A";
            String signCount = "0";
            
            if (metadataMap.containsKey(credId)) {
                CredentialMetadata metadata = metadataMap.get(credId);
                
                // Format creation date/time
                if (metadata.createdAt > 0) {
                    createdAt = formatDatetime(metadata.createdAt);
                }
                
                // Get sign count
                if (metadata.user != null && metadata.user.containsKey("signCount")) {
                    signCount = metadata.user.get("signCount").toString();
                }
                
                // Get user info
                if (metadata.user != null) {
                    String userName = metadata.user.containsKey("name") ? 
                            metadata.user.get("name").toString() : "unknown";
                    String displayName = metadata.user.containsKey("displayName") ? 
                            metadata.user.get("displayName").toString() : "";
                    
                    userInfo = userName;
                    if (!displayName.isEmpty() && !displayName.equals(userName)) {
                        userInfo += " (" + displayName + ")";
                    }
                }
            }
            
            // Format the credential ID to ensure consistent width
            String formattedCredId = credId;
            if (formattedCredId.length() > 30) {
                formattedCredId = formattedCredId.substring(0, 30);
            } else {
                formattedCredId = String.format("%-13s", formattedCredId);
            }
            
            System.out.println(String.format("  [%d] | %s | %s | %3s | %s", 
                i+1, formattedCredId, createdAt, signCount, userInfo));
        }
        System.out.println("-----------------------------------------------------------------------------------------");
        
        System.out.print("Select credential (1-" + credentialIds.size() + "): ");
        int selection = 1; // Default to first credential
        
        try {
            // Usar una forma más robusta de leer la entrada que funcione en diversos contextos
            String input = null;
            // Intentar usar console primero (funciona bien en terminal interactiva)
            if (System.console() != null) {
                input = System.console().readLine();
            } else {
                // Fallback a BufferedReader si console no está disponible
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(System.in))) {
                    input = reader.readLine();
                }
            }
            
            if (input != null && !input.trim().isEmpty()) {
                selection = Integer.parseInt(input.trim());
                if (selection < 1 || selection > credentialIds.size()) {
                    System.out.println("Invalid selection, using first credential.");
                    selection = 1;
                }
            } else {
                System.out.println("No selection made, using first credential.");
            }
        } catch (NumberFormatException e) {
            System.out.println("Invalid input, using first credential.");
        } catch (IOException e) {
            System.out.println("Error reading input: " + e.getMessage() + ", using first credential.");
        }
        
        ByteArray selectedCredential = credentialIds.get(selection - 1);
        System.out.println("Selected credential: " + selectedCredential.getBase64Url());
        return selectedCredential;
    }

    private byte[] createAuthenticatorData(PublicKeyCredentialRequestOptions options, ByteArray credentialId) throws Exception {
        // Get the RP ID hash
        byte[] rpIdHash = HashUtils.sha256(options.getRpId());
        
        // Set the flags (UP=1)
        byte flags = (byte) 0x01; // User Present = true
        
        // Get the signature counter using functional approach
        long signCount = credentialStore.incrementAndSaveSignCount(credentialId);
        
        // Compose the authenticator data
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
        byte[] clientDataHash = HashUtils.sha256(clientDataJson.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        byte[] dataToSign = ByteBuffer.allocate(authenticatorData.length + clientDataHash.length)
            .put(authenticatorData)
            .put(clientDataHash)
            .array();
        
        return SignatureUtils.sign(dataToSign, privateKey);
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
    
    /**
     * Formats a Unix timestamp (in milliseconds) to a human-readable date format yyyy-MM-dd HH:mm
     * 
     * @param timestamp The Unix timestamp in milliseconds
     * @return Formatted date string
     */
    private String formatDatetime(long timestamp) {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        return sdf.format(new Date(timestamp));
    }
}
