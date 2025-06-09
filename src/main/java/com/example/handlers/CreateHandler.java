package com.example.handlers;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.PublicKey;
import java.util.Map;
import java.util.UUID;

import com.example.config.CommandOptions;
import com.example.storage.CredentialMetadata;
import com.example.storage.CredentialStore;
import com.example.storage.KeyStoreManager;
import com.example.utils.CborUtils;
import com.example.utils.CoseKeyUtils;
import com.example.utils.EncodingUtils;
import com.example.utils.HashUtils;
import com.example.utils.PemUtils;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.upokecenter.cbor.CBORObject;
import com.yubico.webauthn.data.AuthenticatorAttestationResponse;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.COSEAlgorithmIdentifier;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import com.yubico.webauthn.data.PublicKeyCredentialParameters;

import lombok.extern.slf4j.Slf4j;

/**
 * Handles the FIDO2 registration (create) operation, simulating an authenticator's credential creation.
 */
@Slf4j
public class CreateHandler extends BaseHandler implements CommandHandler {

    /**
     * Zero AAGUID for software authenticator
     */
    private static final ByteArray AAGUID = new ByteArray(new byte[16]);

    /**
     * Constructs a CreateHandler.
     * @param credentialStore The CredentialStore instance
     * @param jsonMapper The Jackson ObjectMapper
     * @param options The command line options
     */
    public CreateHandler(CredentialStore credentialStore, ObjectMapper jsonMapper, CommandOptions options) {
        super(credentialStore, jsonMapper, options);
    }


    /**
     * Handles the incoming request, using the format specified in options.
     * @param requestJson The JSON string with creation options
     * @return The JSON response formatted according to the specified options
     * @throws Exception if there's an error processing the request
     */
    @Override
    public String handleRequest(String requestJson) throws Exception {
        log.debug("Handling create request with format: {}", options.getFormat());
        
        try {
            return handleCreate(requestJson);
        } catch (Exception e) {
            log.error("Error in create handler: {}", e.getMessage(), e);
            throw e;
        }
    }

    /**
     * Cleans the JSON from unsupported algorithms (other than -7 and -257)
     * @param json The JSON string to clean "pubKeyCredParams"
     * @return The cleaned JSON string
     */
    private ObjectNode cleanUnsupportedAlgorithms(ObjectNode rootNode) {
        try {
            ArrayNode pubKeyCredParams = (ArrayNode) rootNode.path("pubKeyCredParams");
            
            ArrayNode cleanedPubKeyCredParams = jsonMapper.createArrayNode();

            for (JsonNode param : pubKeyCredParams) {
                int alg = param.path("alg").asInt();
                if (alg == -7 || alg == -257) {
                    cleanedPubKeyCredParams.add(param);
                } else {
                    log.debug("Unsupported algorithm: {}", alg);
                }
            }
            
            if(cleanedPubKeyCredParams.size() == 0) {
                throw new IllegalArgumentException("No supported algorithms found in pubKeyCredParams");
            }

            rootNode.set("pubKeyCredParams", cleanedPubKeyCredParams);

            return rootNode;
            
        } catch (Exception e) {
            log.error("Error cleaning JSON from unsupported algorithms: {}", e.getMessage(), e);
            return rootNode;
        }
    }

    /**
     * Handles the creation of a new FIDO2 credential, returning the PublicKeyCredential as JSON.
     * @param optionsJson JSON string for PublicKeyCredentialCreationOptions
     * @return JSON string representing the PublicKeyCredential
     * @throws Exception on error
     */
    public String handleCreate(String optionsJson) throws Exception {
        try {
            // Try to decode base64 if needed
            String decodedOptions = EncodingUtils.tryDecodeBase64Json(optionsJson);
            ObjectNode rootNode = (ObjectNode) jsonMapper.readTree(decodedOptions);
            
            // Clean the JSON from unsupported algorithms
            rootNode = cleanUnsupportedAlgorithms(rootNode);
            
            log.debug("Cleaned JSON: {}", rootNode.toString());

            // We'll use the original challenge as-is
            String originalChallenge = rootNode.get("challenge").asText();

            // Now parse the full options object
            PublicKeyCredentialCreationOptions options = jsonMapper.treeToValue(rootNode, PublicKeyCredentialCreationOptions.class);
            
            // Log the parsed options and the challenge
            log.debug("Parsed options class: {}", options.getClass().getName());
            log.debug("Challenge base64url: {}", options.getChallenge().getBase64Url());
            log.debug("Original Challenge: {}", originalChallenge);

            validateOptions(options);
    
            // 1. Select an algorithm (first supported)
            COSEAlgorithmIdentifier selectedAlg = selectAlgorithm(options);
            
            // 2. Generate credential ID and key pair
            ByteArray credentialId = KeyStoreManager.generateRandomCredentialId();
            KeyPair keyPair = credentialStore.generateAndStoreKeyPair(credentialId, options.getUser().getId(), selectedAlg);

            // 3. Create attestation object
            byte[] attestationObject = createAttestationObject(options, credentialId, keyPair.getPublic(), selectedAlg);

            // 4. Create client data JSON with original challenge format
            String clientDataJson = createClientDataJson(options, originalChallenge);

            // 5. Create response ByteArrays directly (bypass WebAuthn validation)
            ByteArray attestationByteArray = new ByteArray(attestationObject);
            ByteArray clientDataJsonByteArray = new ByteArray(clientDataJson.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            
            // Log response details if verbose
            if(this.options.isVerbose()) {
                logAttestationObject(attestationByteArray.getBytes());
                log.debug("ClientData JSON (original challenge): {}", clientDataJson);
            }
            
            // Initialize the response formatter with the requested format
            log.debug("Using response format: {}", formatter.getFormatName());

            // Create response node with all expected fields (WebAuthn spec)
            ObjectNode credentialNode = jsonMapper.createObjectNode();

            try {
                // Format ID according to the configuration
                formatter.formatBytes(credentialNode, "id", credentialId);
                formatter.formatBytes(credentialNode, "rawId", credentialId);

                formatter.formatString(credentialNode,"type", "public-key");

                // clientExtensionResults at root (with credProps.rk=true)
                ObjectNode clientExtResults = jsonMapper.createObjectNode();
                formatter.formatObject(clientExtResults,"clientExtensionResults", clientExtResults);

                // Build response node with all expected fields (WebAuthn spec)
                ObjectNode responseNode = jsonMapper.createObjectNode();
                
                // Format clientDataJSON according to the configuration (bypassing WebAuthn validation)
                formatter.formatBytes(responseNode, "clientDataJSON", clientDataJsonByteArray);

                // Format attestationObject according to the configuration
                formatter.formatBytes(responseNode, "attestationObject", attestationByteArray);

                // authenticatorAttachment at root (platform / cross-platform) - Chrome extension
                formatter.formatString(credentialNode,"authenticatorAttachment", "platform");

                // Extract and format authenticatorData from attestationObject (CBOR decode)
                try {
                    byte[] attObjBytes = attestationByteArray.getBytes();
                    com.fasterxml.jackson.dataformat.cbor.CBORFactory cborFactory = new com.fasterxml.jackson.dataformat.cbor.CBORFactory();
                    com.fasterxml.jackson.databind.ObjectMapper cborMapper = new com.fasterxml.jackson.databind.ObjectMapper(cborFactory);
                    Map attObjMap = cborMapper.readValue(attObjBytes, Map.class);
                    byte[] authenticatorData = (byte[]) attObjMap.get("authData");
                    if (authenticatorData != null) {
                        formatter.formatBytes(responseNode, "authenticatorData", authenticatorData);
                    }
                } catch (Exception e) {
                    log.warn("Could not extract authenticatorData from attestation object", e);
                }

                // Add transports (Chrome extension)
                ArrayNode transport = jsonMapper.createArrayNode();
                transport.add("internal");
                formatter.formatObject(responseNode,"transports", transport);

                // Add publicKey (DER-encoded SubjectPublicKeyInfo) and algorithm (Chrome extension)
                try {
                    // Get the DER-encoded SubjectPublicKeyInfo
                    byte[] derEncoded = keyPair.getPublic().getEncoded();
                    
                    // Add the raw DER bytes to the response (will be base64url encoded by the formatter)
                    formatter.formatBytes(responseNode, "publicKey", derEncoded);
                    
                    // Add the public key algorithm
                    formatter.formatNumber(responseNode, "publicKeyAlgorithm", selectedAlg.getId());
                    
                    if (log.isDebugEnabled()) {
                        log.debug("Added public key ({} bytes) to response", derEncoded.length);
                    }
                } catch (Exception e) {
                    log.warn("Could not add public key information to response: {}", e.getMessage());
                    if (log.isDebugEnabled()) {
                        log.debug("Public key encoding error", e);
                    }
                }

                // Set the response node in the credential node
                formatter.formatObject(credentialNode,"response", responseNode);
                
                // Convert to JSON string
                String registrationResponseJson = credentialNode.toString();
                
                // Save metadata
                saveMetadata(credentialId, registrationResponseJson, options);
                

                return removeNulls(registrationResponseJson);

            } catch (Exception e) {
                log.error("Error formatting response: {}", e.getMessage(), e);
                throw new RuntimeException("Failed to format response: " + e.getMessage(), e);
            }
        } catch (IOException | KeyStoreException e) {
            log.error("Error during credential creation: {}", e.getMessage(), e);
            throw new Exception("Error during credential creation: " + e.getMessage(), e);
        }
    }

    private void validateOptions(PublicKeyCredentialCreationOptions options) {
        if (options.getPubKeyCredParams().isEmpty()) {
            throw new IllegalArgumentException("No supported algorithms provided");
        }
    }

    private COSEAlgorithmIdentifier selectAlgorithm(PublicKeyCredentialCreationOptions options) {
        return options.getPubKeyCredParams().stream()
            .map(PublicKeyCredentialParameters::getAlg)
            .filter(alg -> alg == COSEAlgorithmIdentifier.ES256 || alg == COSEAlgorithmIdentifier.RS256)
            .findFirst()
            .orElseThrow(() -> new IllegalArgumentException("No supported algorithm found (ES256 or RS256)"));
    }

    private byte[] createAttestationObject(PublicKeyCredentialCreationOptions options, ByteArray credentialId, 
                                         PublicKey publicKey, COSEAlgorithmIdentifier selectedAlg) throws Exception {
        // Generate authenticator data
        byte[] rpIdHash = HashUtils.sha256(options.getRp().getId().getBytes(java.nio.charset.StandardCharsets.UTF_8));
        byte flags = (byte) 0x41; // UP and AT flags
        long signCount = 0;
        ByteArray cosePublicKey = CoseKeyUtils.encodeToCose(publicKey, selectedAlg);
        
        byte[] authData = composeAuthenticatorDataWithAttestedCredentialData(
            rpIdHash, flags, signCount, AAGUID, credentialId, cosePublicKey);
        
        // Create attestation object as CBOR map with format "none" (no attestation)
        CBORFactory cborFactory = new CBORFactory();
        ObjectMapper cborWriter = new ObjectMapper(cborFactory);
        
        // Create a map with the required fields for an attestation object
        java.util.Map<String, Object> attestationObject = new java.util.LinkedHashMap<>();
        attestationObject.put("fmt", "none");  // Use "none" attestation format
        attestationObject.put("authData", authData);
        attestationObject.put("attStmt", new java.util.LinkedHashMap<>()); // Empty attestation statement
        
        // Encode the map to CBOR
        return cborWriter.writeValueAsBytes(attestationObject);
    }

    private String createClientDataJson(PublicKeyCredentialCreationOptions options, String originalChallenge) throws JsonProcessingException {
        ObjectNode clientData = jsonMapper.createObjectNode();
        clientData.put("type", "webauthn.create");
        
        // Add original challenge and origin to the client data
        clientData.put("challenge", originalChallenge);
        clientData.put("origin", "https://" + options.getRp().getId());
        
        // Create the JSON string
        String json = clientData.toString();
        log.debug("Final client data JSON: {}", json);
        
        return json;
    }

    /**
     * Utility method to convert bytes to hex string for debugging
     */
    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
    
    /**
     * Creates an AuthenticatorAttestationResponse from attestation object and client data JSON.
     * @param attestationObject The attestation object bytes
     * @param clientDataJson The client data JSON string
     * @return The attestation response
     */
    private AuthenticatorAttestationResponse createAttestationResponse(byte[] attestationObject, String clientDataJson) {
        try {
            // Convert raw bytes directly - no intermediate conversions
            ByteArray attestationByteArray = new ByteArray(attestationObject);
            
            // For client data JSON, ensure proper encoding and bypass WebAuthn validation
            // that expects Base64URL challenge format by creating ByteArray directly
            byte[] clientDataJsonBytes = clientDataJson.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            ByteArray clientDataJsonByteArray = new ByteArray(clientDataJsonBytes);
            
            // Build the response without triggering CollectedClientData validation
            return AuthenticatorAttestationResponse.builder()
                .attestationObject(attestationByteArray)
                .clientDataJSON(clientDataJsonByteArray)
                .build();
        } catch (Exception e) {
            throw new IllegalArgumentException("Error creating attestation response: " + e.getMessage(), e);
        }
    }

    private void logAttestationObject(byte[] attestationBytes) {
        try {
            CBORFactory cborFactory = new CBORFactory();
            ObjectMapper cborReader = new ObjectMapper(cborFactory);
            JsonNode cborData = cborReader.readTree(attestationBytes);
            
            log.debug("AttestationObject (decoded):\n{}", cborData.toPrettyString());

            log.debug("AuthData (decoded):\n{}", decodeAuthData(cborData.get("authData").binaryValue()));

        } catch (Exception e) {
            log.warn("Could not decode attestationObject: {}", e.getMessage());
        }
    }

    /**
     * Saves credential metadata.
     * @param credentialId The credential ID
     * @param registrationResponseJson The registration response JSON
     * @param options The creation options
     * @throws KeyStoreException if an error occurs with the keystore
     */
    private void saveMetadata(ByteArray credentialId, String registrationResponseJson, 
                            PublicKeyCredentialCreationOptions options) throws KeyStoreException {
        if (credentialStore != null) {
            try {
                CredentialMetadata meta = new CredentialMetadata();
                meta.credentialId = credentialId.getBase64Url();
                meta.registrationResponseJson = registrationResponseJson;
                meta.createdAt = System.currentTimeMillis();
                meta.rp = jsonMapper.convertValue(options.getRp(), 
                    new com.fasterxml.jackson.core.type.TypeReference<Map<String, Object>>() {});
                meta.user = jsonMapper.convertValue(options.getUser(), 
                    new com.fasterxml.jackson.core.type.TypeReference<Map<String, Object>>() {});
                
                try {
                    // Usar Optional para obtener la clave pública
                    meta.publicKeyPem = credentialStore.getPublicKey(credentialId)
                        .map(PemUtils::publicKeyToPem)
                        .orElse(null);
                } catch (KeyStoreException e) {
                    meta.publicKeyPem = null;
                }
                
                // Usar el nuevo método addCredentialMetadata() en lugar de intentar modificar el mapa directamente
                credentialStore.addCredentialMetadata(meta.credentialId, meta);
                credentialStore.saveMetadata();
            } catch (IOException e) {
                throw new KeyStoreException("Failed to save metadata: " + e.getMessage(), e);
            }
        }
    }

    private static byte[] composeAuthenticatorDataWithAttestedCredentialData(
            byte[] rpIdHash, byte flags, long signCount, ByteArray aaguid, 
            ByteArray credentialId, ByteArray cosePublicKey) {
        byte[] aaguidBytes = aaguid.getBytes();
        byte[] credIdBytes = credentialId.getBytes();
        byte[] coseBytes = cosePublicKey.getBytes();
        byte[] lengthBytes = new byte[] { (byte) (credIdBytes.length >> 8), (byte) (credIdBytes.length & 0xFF) };
        byte[] signCountBytes = ByteBuffer.allocate(4).putInt((int) signCount).array();
        
        int total = 32 + 1 + 4 + 16 + 2 + credIdBytes.length + coseBytes.length;
        byte[] out = new byte[total];
        int offset = 0;
        
        System.arraycopy(rpIdHash, 0, out, offset, 32); offset += 32;
        out[offset++] = flags;
        System.arraycopy(signCountBytes, 0, out, offset, 4); offset += 4;
        System.arraycopy(aaguidBytes, 0, out, offset, 16); offset += 16;
        System.arraycopy(lengthBytes, 0, out, offset, 2); offset += 2;
        System.arraycopy(credIdBytes, 0, out, offset, credIdBytes.length); offset += credIdBytes.length;
        System.arraycopy(coseBytes, 0, out, offset, coseBytes.length);
        
        return out;
    }


    /**
     * Decodes the authenticator data and returns a human-readable representation.
     * @param authData The raw authenticator data bytes
     * @return A string containing the decoded components
     */
    public String decodeAuthData(byte[] authData) {
        if (authData == null || authData.length < 37) {
            return "Invalid authData (too short)";
        }

        // Extract rpIdHash (first 32 bytes)
        byte[] rpIdHash = new byte[32];
        System.arraycopy(authData, 0, rpIdHash, 0, 32);
        
        // Extract flags (1 byte)
        byte flags = authData[32];
        boolean userPresent = (flags & 0x01) != 0;
        boolean userVerified = (flags & 0x04) != 0;
        boolean attestedCredentialData = (flags & 0x40) != 0;
        boolean extensionDataIncluded = (flags & 0x80) != 0;
        
        // Extract signCount (4 bytes)
        int signCount = ByteBuffer.wrap(authData, 33, 4).getInt();
        ObjectNode authDataNode = jsonMapper.createObjectNode();

        authDataNode.put("rpIdHash", new ByteArray(rpIdHash).getHex());
        authDataNode.put("flags", String.format("%02X", flags));
        authDataNode.put("userPresent", userPresent ? "1" : "0");
        authDataNode.put("userVerified", userVerified ? "1" : "0");
        authDataNode.put("attestedCredentialData", attestedCredentialData ? "1" : "0");
        authDataNode.put("extensionDataIncluded", extensionDataIncluded ? "1" : "0");
        authDataNode.put("signCount", signCount);
        
        // If attested credential data is present, decode it
        if (attestedCredentialData && authData.length >= 55) {
            // Extract AAGUID (16 bytes)
            byte[] aaguid = new byte[16];
            System.arraycopy(authData, 37, aaguid, 0, 16);
            
            // Format AAGUID as UUID
            UUID aaguidUuid = getUuidFromBytes(aaguid);
            
            // Extract credentialIdLength (2 bytes)
            int credentialIdLength = ((authData[53] & 0xFF) << 8) | (authData[54] & 0xFF);
            
            authDataNode.put("aaguid", aaguidUuid.toString());
            authDataNode.put("credentialIdLength", credentialIdLength);
            
            // Extract credentialId (variable length)
            if (authData.length >= 55 + credentialIdLength) {
                byte[] credentialId = new byte[credentialIdLength];
                System.arraycopy(authData, 55, credentialId, 0, credentialIdLength);
                authDataNode.put("credentialId", EncodingUtils.base64UrlEncode(credentialId));
                
                // The rest is CBOR-encoded public key
                int publicKeyOffset = 55 + credentialIdLength;
                if (authData.length > publicKeyOffset) {
                    byte[] publicKeyCbor = new byte[authData.length - publicKeyOffset];
                    System.arraycopy(authData, publicKeyOffset, publicKeyCbor, 0, publicKeyCbor.length);
                    // Decode CBOR to JSON and convert to DER format
                    try {
                        // Decode the CBOR data to a Map
                        CBORObject cborObj = CBORObject.DecodeFromBytes(publicKeyCbor);
                        
                        Map<Object, Object> coseKey = CborUtils.decodeToMap(new ByteArray(cborObj.EncodeToBytes()));

                        // Add the raw COSE key to the output
                        ObjectNode keyNode = jsonMapper.createObjectNode();
                        keyNode.put("cbor", EncodingUtils.base64UrlEncode(publicKeyCbor));
                        
                        // Try to convert to DER format
                        try {
                            byte[] derEncoded = CoseKeyUtils.coseToDer(coseKey);
                            keyNode.put("der", EncodingUtils.base64UrlEncode(derEncoded));
                            
                            // Add key details based on type
                            int keyType = ((Number) coseKey.get(1)).intValue();

                            if (keyType == 2) { // EC2 key
                                keyNode.put("keyType", "EC2");
                                keyNode.put("crv", coseKey.get(-1).toString());
                                keyNode.put("x", EncodingUtils.base64UrlEncode((byte[]) coseKey.get(-2)));
                                keyNode.put("y", EncodingUtils.base64UrlEncode((byte[]) coseKey.get(-3)));
                            } else if (keyType == 3) { // RSA key
                                keyNode.put("keyType", "RSA");
                                keyNode.put("n", EncodingUtils.base64UrlEncode((byte[]) coseKey.get(-1)));
                                keyNode.put("e", EncodingUtils.base64UrlEncode((byte[]) coseKey.get(-2)));
                            }
                            
                        } catch (Exception e) {
                            log.warn("Failed to convert COSE to DER: {}", e.getMessage());
                            keyNode.put("error", "Failed to convert to DER: " + e.getMessage());
                        }
                        
                        // Add the public key to the response
                        authDataNode.set("credentialPublicKey", keyNode);
                        
                    } catch (Exception e) {
                        log.warn("Failed to decode publicKeyCbor: {}", e.getMessage());
                        authDataNode.put("credentialPublicKey", EncodingUtils.base64UrlEncode(publicKeyCbor));
                        authDataNode.put("decodingError", "Failed to decode publicKeyCbor: " + e.getMessage());
                    }
                }
            }
        }
        
        return authDataNode.toPrettyString();
    }
    
    /**
     * Converts a byte array to a UUID.
     */
    private UUID getUuidFromBytes(byte[] bytes) {
        ByteBuffer bb = ByteBuffer.wrap(bytes);
        long high = bb.getLong();
        long low = bb.getLong();
        return new UUID(high, low);
    }
}
