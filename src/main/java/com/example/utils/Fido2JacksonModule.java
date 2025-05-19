package com.example.utils;

import com.fasterxml.jackson.databind.module.SimpleModule;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.COSEAlgorithmIdentifier;

/**
 * Custom Jackson module for FIDO2 Client Simulator that registers specialized 
 * deserializers for WebAuthn data types.
 * <p>
 * This module provides compatibility with different WebAuthn serialization formats
 * used by various identity providers like PingOne, Azure, Auth0, etc.
 * </p>
 * 
 * @author Jordi Murgo
 */
public class Fido2JacksonModule extends SimpleModule {
    
    private static final long serialVersionUID = 1L;

    public Fido2JacksonModule() {
        super("Fido2JacksonModule");
        
        // Register the ByteArray deserializer that handles both base64, base64url strings and 
        // arrays of bytes (as used by PingOne and potentially other providers)
        addDeserializer(ByteArray.class, new ByteArrayDeserializer());
    }
}
