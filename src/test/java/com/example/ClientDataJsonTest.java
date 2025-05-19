package com.example;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.yubico.webauthn.data.ByteArray;
import org.junit.jupiter.api.Test;
import java.util.Base64;

public class ClientDataJsonTest {
    
    @Test
    public void testChallengeEncoding() throws Exception {
        // This is the challenge from the registration options
        String challengeStr = "FPR08HObgp8zL66IIt6DnS03JSWKRZcPexqSeXf_wO2OvNjmmpV8d8KEDQRM5-LLvp_1F2DYpCejX45uOGnekQ";
        
        // Decode and re-encode to base64url to ensure consistent formatting
        byte[] challengeBytes = Base64.getUrlDecoder().decode(challengeStr);
        String base64UrlChallenge = Base64.getUrlEncoder().withoutPadding().encodeToString(challengeBytes);
        
        // Create client data JSON
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode clientData = mapper.createObjectNode();
        clientData.put("type", "webauthn.create");
        clientData.put("challenge", base64UrlChallenge);
        clientData.put("origin", "https://webauthn.io");
        
        // Print the results
        System.out.println("Original challenge: " + challengeStr);
        System.out.println("Decoded bytes length: " + challengeBytes.length);
        System.out.println("Re-encoded base64url: " + base64UrlChallenge);
        System.out.println("Client Data JSON: " + clientData.toString());
        
        // Also create using the raw string approach
        String rawJson = String.format(
            "{\"type\":\"webauthn.create\",\"challenge\":\"%s\",\"origin\":\"https://webauthn.io\"}",
            base64UrlChallenge
        );
        System.out.println("Raw JSON: " + rawJson);
        
        // Compare the two JSON strings
        System.out.println("JSON strings match: " + clientData.toString().equals(rawJson));
    }
}
