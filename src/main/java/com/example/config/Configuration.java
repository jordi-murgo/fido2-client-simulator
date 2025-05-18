package com.example.config;

import java.util.HashMap;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Configuration class for response format mappings.
 */
@Data
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Configuration {
    @JsonProperty("formats")
    private Map<String, Map<String, String>> formats = new HashMap<>();
    
    @JsonProperty("keystore")
    private KeystoreConfig keystore;

    @JsonProperty("logLevel")
    private String logLevel;
    
    /**
     * Constructor for FormatConfig.
     * @param formats The format configurations to initialize with
     */
    @JsonCreator
    public Configuration(@JsonProperty("formats") Map<String, Map<String, String>> formats,
                  @JsonProperty("keystore") KeystoreConfig keystore) {
        if (formats != null) {
            this.formats = new HashMap<>(formats);
        }
        this.keystore = keystore;
    }

    /**
     * Sets a format configuration.
     * @param name The name of the format configuration
     * @param format The format configuration to set
     */
    @JsonAnySetter
    public void setFormat(String name, Map<String, String> format) {
        formats.put(name, format);
    }

    /**
     * Gets all format configurations.
     * @return The format configurations
     */
    @JsonAnyGetter
    public Map<String, Map<String, String>> getFormats() {
        return formats;
    }
        
    /**
     * Gets the format configuration for a specific format name.
     * @param formatName The name of the format configuration to retrieve
     * @return The format configuration, or null if not found
     */
    public Map<String, String> getFormat(String formatName) {
        return formats != null ? formats.get(formatName) : null;
    }
        
    /**
     * Checks if a specific format configuration exists.
     * @param formatName The name of the format configuration to check
     * @return true if the format exists, false otherwise
     */
    public boolean hasFormat(String formatName) {
        return formats != null && formats.containsKey(formatName);
    }

    @Data
    @NoArgsConstructor
    public static class KeystoreConfig {
        @JsonProperty("path")
        private String path;
        
        @JsonProperty("password")
        private String password;

        @JsonProperty("metadataPath")
        private String metadataPath;
    }
}
