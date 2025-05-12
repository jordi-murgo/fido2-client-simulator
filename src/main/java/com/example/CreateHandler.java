package com.example;

import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.yubico.webauthn.data.AuthenticatorAttestationResponse;
import com.yubico.webauthn.data.AuthenticatorData;
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.COSEAlgorithmIdentifier;
import com.yubico.webauthn.data.ClientRegistrationExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import com.yubico.webauthn.data.PublicKeyCredentialParameters;
import com.yubico.webauthn.data.UserVerificationRequirement;

/**
 * Handles the FIDO2 registration (create) operation, simulating an authenticator's credential creation.
 */
public class CreateHandler {

    private final KeyStoreManager keyStoreManager;
    private final ObjectMapper jsonMapper;
    private static final ByteArray AAGUID = new ByteArray(new byte[16]); // Zero AAGUID for software authenticator

    /**
     * Constructs a CreateHandler.
     * @param keyStoreManager The KeyStoreManager instance
     * @param jsonMapper The Jackson ObjectMapper
     */
    public CreateHandler(KeyStoreManager keyStoreManager, ObjectMapper jsonMapper) {
        this.keyStoreManager = keyStoreManager;
        this.jsonMapper = jsonMapper;
        this.jsonMapper.setSerializationInclusion(com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL);
    }

    /**
     * Handles the creation of a new FIDO2 credential, returning the PublicKeyCredential as JSON.
     * @param optionsJson JSON string for PublicKeyCredentialCreationOptions
     * @return JSON string representing the PublicKeyCredential
     * @throws Exception on error
     */
    public String handleCreate(String optionsJson) throws Exception {
        // Attempt to decode Base64-encoded JSON (supports URL-safe and standard Base64)
        optionsJson = Util.tryDecodeBase64Json(optionsJson);

        // Parse the options
        PublicKeyCredentialCreationOptions options = jsonMapper.readValue(optionsJson, PublicKeyCredentialCreationOptions.class);

        // 1. Select an algorithm (first supported)
        COSEAlgorithmIdentifier selectedAlg = options.getPubKeyCredParams().stream()
            .map(PublicKeyCredentialParameters::getAlg)
            .filter(alg -> alg == COSEAlgorithmIdentifier.ES256 || alg == COSEAlgorithmIdentifier.RS256)
            .findFirst()
            .orElseThrow(() -> new IllegalArgumentException("No supported algorithm found (ES256 or RS256)"));

        // 2. Generate Credential ID
        ByteArray credentialId = KeyStoreManager.generateRandomCredentialId();

        // 3. Generate Key Pair and store it
        KeyPair keyPair = keyStoreManager.generateAndStoreKeyPair(credentialId, options.getUser().getId(), selectedAlg);

        // 4. Construct AuthenticatorData
        byte[] rpIdHash = Util.sha256(options.getRp().getId());
        byte flags = (byte) 0b01000001; // UP=1, AT=1
        if (options.getAuthenticatorSelection().flatMap(AuthenticatorSelectionCriteria::getUserVerification).orElse(UserVerificationRequirement.DISCOURAGED) == UserVerificationRequirement.REQUIRED) {
            flags |= (byte) 0b00000100; // Set UV bit
        }
        long signCount = 0;

        // Manually encode public key as COSE ByteArray
        ByteArray cosePublicKey = UtilPublicKeyCose.encodeToCose(keyPair.getPublic(), selectedAlg);
        // Compose authenticator data bytes with attested credential data
        byte[] authDataBytes = composeAuthenticatorDataWithAttestedCredentialData(
            rpIdHash, flags, signCount, AAGUID, credentialId, cosePublicKey
        );
        AuthenticatorData authData = new AuthenticatorData(new ByteArray(authDataBytes));

        // 5. Construct clientDataJSON
        ObjectNode clientData = jsonMapper.createObjectNode();
        clientData.put("type", "webauthn.create");
        clientData.put("challenge", options.getChallenge().getBase64Url());
        clientData.put("origin", "https://" + options.getRp().getId());
        String clientDataJsonString = jsonMapper.writeValueAsString(clientData);
        ByteArray clientDataJsonBytes = new ByteArray(clientDataJsonString.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        ByteArray clientDataHash = new ByteArray(Util.sha256(clientDataJsonBytes.getBytes()));

        // 6. Attestation Statement ("packed" self-attestation)
        ByteBuffer signedData = ByteBuffer.allocate(authData.getBytes().size() + clientDataHash.size());
        signedData.put(authData.getBytes().getBytes());
        signedData.put(clientDataHash.getBytes());

        Signature signature = Signature.getInstance(getSignatureAlgorithm(selectedAlg), KeyStoreManager.PROVIDER);
        signature.initSign(keyPair.getPrivate());
        signature.update(signedData.array());

        // Compose attestation object (CBOR map)
        Map<String, Object> attestationObjectMap = new LinkedHashMap<>();
        attestationObjectMap.put("fmt", "none");
        attestationObjectMap.put("authData", authDataBytes);
        attestationObjectMap.put("attStmt", Collections.emptyMap());
        ByteArray attestationObjectCbor = CborUtil.encodeMap(attestationObjectMap);

        AuthenticatorAttestationResponse response = AuthenticatorAttestationResponse.builder()
            .attestationObject(attestationObjectCbor)
            .clientDataJSON(clientDataJsonBytes)
            .build();

        PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> credential =
            PublicKeyCredential.<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs>builder()
                .id(credentialId)
                .response(response)
                .clientExtensionResults(ClientRegistrationExtensionOutputs.builder().build())
                .build();

        String registrationResponseJson = jsonMapper.writerWithDefaultPrettyPrinter().writeValueAsString(credential);

        
        // Log attestationObject fields (fmt, authData, attStmt) in CLI
        try {
            // Parse the registration response JSON to extract attestationObject
            com.fasterxml.jackson.databind.JsonNode responseNode = jsonMapper.readTree(registrationResponseJson).get("response");
            String attestationB64 = responseNode.get("attestationObject").asText();
            // Convert from Base64URL to bytes
            byte[] attestationBytes = java.util.Base64.getUrlDecoder().decode(attestationB64);
            
            // Crear un ObjectMapper con CBORFactory para parsear datos CBOR
            com.fasterxml.jackson.dataformat.cbor.CBORFactory cborFactory = new com.fasterxml.jackson.dataformat.cbor.CBORFactory();
            com.fasterxml.jackson.databind.ObjectMapper cborReader = new com.fasterxml.jackson.databind.ObjectMapper(cborFactory);
            com.fasterxml.jackson.databind.JsonNode cborData = cborReader.readTree(attestationBytes);
            
            System.out.println("=== AttestationObject (decoded) ===");
            System.out.println("fmt: " + cborData.get("fmt"));
            
            // Get authData as binary and decode it
            byte[] rawAuthData = cborData.get("authData").binaryValue();
            System.out.println("authData (base64): " + java.util.Base64.getEncoder().encodeToString(rawAuthData));
            
            // Decode and print authData structure in detail
            System.out.println("\n--- AuthData Structure ---");
            System.out.println(UtilAuthData.decodeAuthData(rawAuthData));
            System.out.println("------------------------");
            
            System.out.println("attStmt: " + cborData.get("attStmt"));
            System.out.println("==============================");
        } catch (Exception e) {
            System.out.println("[WARN] Could not decode attestationObject: " + e.getMessage());
        }

        // Save metadata (registration response, rp, user) via KeyStoreManager
        if (keyStoreManager != null) {
            CredentialMetadata meta = new CredentialMetadata();
            meta.credentialId = credentialId.getBase64Url();
            meta.registrationResponseJson = registrationResponseJson;
            meta.createdAt = System.currentTimeMillis();
            meta.rp = jsonMapper.convertValue(options.getRp(), new com.fasterxml.jackson.core.type.TypeReference<java.util.Map<String, Object>>() {});
            meta.user = jsonMapper.convertValue(options.getUser(), new com.fasterxml.jackson.core.type.TypeReference<java.util.Map<String, Object>>() {});
            // Extract public key from keystore and encode as PEM
            try {
                PublicKey pubKey = keyStoreManager.getPublicKey(credentialId);
                if (pubKey != null) {
                    meta.publicKeyPem = UtilPem.publicKeyToPem(pubKey);
                } else {
                    meta.publicKeyPem = null;
                }
            } catch (KeyStoreException e) {
                meta.publicKeyPem = null;
            }
            keyStoreManager.metadataMap.put(meta.credentialId, meta);
            keyStoreManager.saveMetadata();
        }

        // Add rawId to the response
        ObjectNode root = jsonMapper.readValue(registrationResponseJson, ObjectNode.class);
        root.set("rawId", root.get("id"));
        registrationResponseJson = jsonMapper.writeValueAsString(root);
        
        return registrationResponseJson;
    }

    private String getSignatureAlgorithm(COSEAlgorithmIdentifier coseAlg) {
        if (COSEAlgorithmIdentifier.ES256.equals(coseAlg)) {
            return "SHA256withECDSA";
        } else if (COSEAlgorithmIdentifier.RS256.equals(coseAlg)) {
            return "SHA256withRSA";
        }
        throw new IllegalArgumentException("Unsupported COSE algorithm for JCA signature: " + coseAlg);
    }

    /**
     * Compose the authenticator data byte array with attested credential data for WebAuthn spec.
     * Layout: rpIdHash (32), flags (1), signCount (4), attestedCredentialData (AAGUID (16), credentialIdLen (2), credentialId, coseKey)
     */
    private static byte[] composeAuthenticatorDataWithAttestedCredentialData(byte[] rpIdHash, byte flags, long signCount, ByteArray aaguid, ByteArray credentialId, ByteArray cosePublicKey) {
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
}
