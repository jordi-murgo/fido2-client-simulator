package com.example.handlers;

import com.example.config.CommandOptions;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.example.storage.CredentialStore;

/**
 * Factory for creating credential handlers based on the requested operation and promotes extensibility.
 * Implements the Factory Method pattern for handler creation.
 */
public class HandlerFactory {
    private final CredentialStore credentialStore;
    private final ObjectMapper jsonMapper;
    
    /**
     * Constructs a HandlerFactory.
     * @param credentialStore The credential store to use
     * @param jsonMapper The JSON mapper to use
     */
    public HandlerFactory(CredentialStore credentialStore, ObjectMapper jsonMapper) {
        this.credentialStore = credentialStore;
        this.jsonMapper = jsonMapper;
    }
    
    /**
     * Creates a credential handler for the specified operation.
     * 
     * @param operation the operation to create a handler for (create, get, info)
     * @param options the command line options
     * @return a credential handler for the specified operation
     * @throws IllegalArgumentException if the operation is unknown
     */
    public CommandHandler createHandler(String operation, CommandOptions options) {
        if ("create".equalsIgnoreCase(operation)) {
            return new CreateHandler(credentialStore, jsonMapper, options);
        } else if ("get".equalsIgnoreCase(operation)) {
            return new GetHandler(credentialStore, jsonMapper, options);
        } else if ("info".equalsIgnoreCase(operation)) {
            return new InfoHandler(credentialStore, jsonMapper, options);
        }
        
        throw new IllegalArgumentException("Unknown operation: " + operation);
    }
}
