package com.example;

import java.util.Map;

/**
 * Represents the metadata associated with a FIDO2 credential, including registration response, RP and user info.
 */
public class CredentialMetadata {
    /**
     * The credential ID (Base64Url).
     */
    public String credentialId;

    /**
     * The full registration response as JSON string.
     */
    public String registrationResponseJson;

    /**
     * The relying party (RP) information as a map.
     */
    public Map<String, Object> rp;

    /**
     * The user information as a map.
     */
    public Map<String, Object> user;

    /**
     * Creation timestamp (epoch millis).
     */
    public long createdAt;

    /**
     * The public key in PEM format (X.509 SubjectPublicKeyInfo), associated with this credential.
     * This enables signature verification and interoperability outside the Java KeyStore.
     */
    public String publicKeyPem;
}

