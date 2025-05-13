package com.example.handlers;

/**
 * Interface for FIDO2 credential handlers.
 * Promotes testability and allows for alternative handler implementations.
 */
public interface CommandHandler {
    /**
     * Handles a FIDO2 request and returns the response as a JSON string.
     * @param requestJson The input request JSON
     * @return The response JSON
     * @throws Exception if processing fails
     */
    String handleRequest(String requestJson) throws Exception;
}
