package com.example.storage;

import java.util.Map;

/**
 * Stores metadata about a credential.
 */
public class CredentialMetadata {
    public String credentialId;
    public String registrationResponseJson;
    public long createdAt;
    public Map<String, Object> rp;
    public Map<String, Object> user;
    public String publicKeyPem;
}
