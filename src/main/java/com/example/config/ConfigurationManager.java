package com.example.config;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

import com.example.config.Configuration.KeystoreConfig;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import lombok.extern.slf4j.Slf4j;

/**
 * Manages configuration loading and access for the FIDO2 Client Simulator.
 * Loads configuration from properties files and YAML format configurations.
 */
@Slf4j
public class ConfigurationManager {
    
    private static final String DEFAULT_FORMAT_CONFIG_PATH = "configuration.yaml";
    
    private Configuration configuration = new Configuration();
    private boolean loaded = false;
    
    // Singleton instance holder
    private static class Holder {
        private static final ConfigurationManager INSTANCE = new ConfigurationManager();
    }
    
    private ConfigurationManager() {
        try {
            loadFormatConfiguration(DEFAULT_FORMAT_CONFIG_PATH);
            loaded = true;
        } catch (Exception e) {
            log.error("Failed to initialize ConfigurationManager", e);
            throw new RuntimeException("Failed to initialize ConfigurationManager", e);
        }
    }
    
    /**
     * Gets the singleton instance of the ConfigurationManager.
     * 
     * @return The ConfigurationManager instance
     */
    public static ConfigurationManager getInstance() {
        return Holder.INSTANCE;
    }
    
    /**
     * Loads format configuration from the specified path or classpath.
     *
     * @param configPath the path to the format configuration file
     * @return the loaded FormatConfig instance
     */
    public Configuration loadFormatConfiguration(String configPath) {
        if (configPath == null) {
            configPath = DEFAULT_FORMAT_CONFIG_PATH;
        }
        
        File configFile = new File(configPath);
        if (configFile.exists()) {
            try (InputStream input = new FileInputStream(configFile)) {
                ObjectMapper yamlMapper = new ObjectMapper(new YAMLFactory());
                this.configuration = yamlMapper.readValue(input, Configuration.class);
                log.info("Loaded format configuration from: {}", configFile.getAbsolutePath());
                return this.configuration;
            } catch (Exception e) {
                log.error("Error loading format configuration from file: " + configPath, e);
                return loadDefaultFormatConfiguration();
            }
        } else {
            // Try to load from classpath
            try (InputStream input = getClass().getClassLoader().getResourceAsStream(configPath)) {
                if (input != null) {
                    ObjectMapper yamlMapper = new ObjectMapper(new YAMLFactory());
                    this.configuration = yamlMapper.readValue(input, Configuration.class);
                    log.info("Loaded format configuration from classpath: {}", configPath);
                    return this.configuration;
                } else {
                    log.warn("Format configuration file not found: {}", configPath);
                    return loadDefaultFormatConfiguration();
                }
            } catch (Exception e) {
                log.error("Error loading format configuration from classpath: " + configPath, e);
                return loadDefaultFormatConfiguration();
            }
        }
    }
    

    /**
     * Loads the default format configuration with predefined values.
     * This is used when no configuration file is found or when explicitly requested.
     * 
     * @return the default FormatConfig instance with predefined format values
     */
    private Configuration loadDefaultFormatConfiguration() {
        Configuration config = new Configuration();
        
        Map<String, String> defaultFormat = new HashMap<>();
        defaultFormat.put("id", "base64url");
        defaultFormat.put("rawId", "base64url");
        defaultFormat.put("authenticatorData", "base64url");
        defaultFormat.put("publicKey", "base64url");
        defaultFormat.put("attestationObject", "base64url");
        defaultFormat.put("clientDataJSON", "string");
        defaultFormat.put("signature", "base64url");
        defaultFormat.put("userHandle", "base64url");
        
        config.setFormat("default", defaultFormat);

        KeystoreConfig keystoreConfig = new KeystoreConfig();
        keystoreConfig.setPath("fido2_keystore.p12");
        keystoreConfig.setPassword("changeme");
        keystoreConfig.setMetadataPath("fido2_keystore_metadata.json");
        config.setKeystore(keystoreConfig);

        log.info("Loaded default format configuration");
        this.configuration = config;
        
        return config;
    }
    
    /**
     * Gets the format configuration for the specified format name.
     * If the format configuration hasn't been loaded yet, it will be loaded first.
     * If the format is not found, it will return null.
     * 
     * @param formatName the name of the format configuration to get
     * @return the format configuration, or null if not found
     */
    public Map<String, String> getFormatConfig(String formatName) {
        // If formatName is null, return null
        if (formatName == null) {
            return null;
        }
        
        // Get the requested format
        if(configuration.hasFormat(formatName)) {
            return configuration.getFormat(formatName);
        }
        
        return null;
    }
 
    /**
     * Gets the keystore file path.
     * 
     * @return The keystore file path
     */
    public String getKeystorePath() {
        return configuration.getKeystore().getPath();
    }
    
    /**
     * Gets the metadata file path.
     * 
     * @return The metadata file path
     */
    public String getMetadataPath() {
        return configuration.getKeystore().getMetadataPath();
    }
    
    /**
     * Gets the keystore password.
     * 
     * @return The keystore password
     */
    public String getKeystorePassword() {
        return configuration.getKeystore().getPassword();
    }
    
    /**
     * Checks if the configuration was successfully loaded from a file.
     * 
     * @return true if a configuration file was loaded, false otherwise
     */
    public boolean isLoaded() {
        return loaded;
    }
}
