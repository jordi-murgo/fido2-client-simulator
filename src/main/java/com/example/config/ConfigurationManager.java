package com.example.config;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Configuration manager for the FIDO2 Client Simulator.
 * Provides centralized access to all configuration properties.
 * 
 * @author Jordi Murgo
 * @since 1.1
 */
public class ConfigurationManager {
    private static final Logger LOGGER = Logger.getLogger(ConfigurationManager.class.getName());
    
    // Default configuration values
    private static final String DEFAULT_KEYSTORE_PATH = "fido2_keystore.p12";
    private static final String DEFAULT_METADATA_PATH = "fido2_metadata.json";
    private static final String DEFAULT_KEYSTORE_PASSWORD = "fido2simulator";
    
    // Configuration file locations
    private static final String[] CONFIG_LOCATIONS = {
        "fido2_config.properties",                      // Current directory
        System.getProperty("user.home") + "/.fido2/config.properties", // User home directory
        "/etc/fido2/config.properties"                  // System-wide configuration
    };
    
    private static ConfigurationManager instance;
    private Properties properties = new Properties();
    private boolean loaded = false;
    
    /**
     * Gets the singleton instance of the ConfigurationManager.
     * 
     * @return The ConfigurationManager instance
     */
    public static synchronized ConfigurationManager getInstance() {
        if (instance == null) {
            instance = new ConfigurationManager();
        }
        return instance;
    }
    
    private ConfigurationManager() {
        loadConfiguration();
    }
    
    /**
     * Loads configuration from a properties file.
     * Checks multiple locations in order of precedence.
     */
    private void loadConfiguration() {
        // First try loading from specified locations
        for (String location : CONFIG_LOCATIONS) {
            Path configPath = Paths.get(location);
            if (Files.exists(configPath)) {
                try (InputStream input = new FileInputStream(configPath.toFile())) {
                    properties.load(input);
                    LOGGER.log(Level.INFO, "Configuration loaded from: {0}", configPath);
                    loaded = true;
                    return;
                } catch (IOException e) {
                    LOGGER.log(Level.WARNING, "Failed to load configuration from: " + configPath, e);
                }
            }
        }
        
        // If no configuration file found, then load from classpath
        try (InputStream input = getClass().getClassLoader().getResourceAsStream("fido2_config.properties")) {
            if (input != null) {
                properties.load(input);
                LOGGER.log(Level.INFO, "Configuration loaded from classpath");
                loaded = true;
                return;
            }
        } catch (IOException e) {
            LOGGER.log(Level.WARNING, "Failed to load configuration from classpath", e);
        }
        
        // If we get here, no configuration was loaded
        LOGGER.log(Level.INFO, "No configuration file found, using default values");
    }
    
    /**
     * Gets the keystore file path.
     * 
     * @return The keystore file path
     */
    public String getKeystorePath() {
        return properties.getProperty("keystore.path", DEFAULT_KEYSTORE_PATH);
    }
    
    /**
     * Gets the metadata file path.
     * 
     * @return The metadata file path
     */
    public String getMetadataPath() {
        return properties.getProperty("metadata.path", DEFAULT_METADATA_PATH);
    }
    
    /**
     * Gets the keystore password.
     * 
     * @return The keystore password
     */
    public String getKeystorePassword() {
        return properties.getProperty("keystore.password", DEFAULT_KEYSTORE_PASSWORD);
    }
    
    /**
     * Gets a configuration property.
     * 
     * @param key The property key
     * @param defaultValue The default value if the property is not found
     * @return The property value, or the default value if not found
     */
    public String getProperty(String key, String defaultValue) {
        return properties.getProperty(key, defaultValue);
    }
    
    /**
     * Gets a configuration property as an integer.
     * 
     * @param key The property key
     * @param defaultValue The default value if the property is not found or is not a valid integer
     * @return The property value as an integer, or the default value if not found or not a valid integer
     */
    public int getIntProperty(String key, int defaultValue) {
        String value = properties.getProperty(key);
        if (value == null) return defaultValue;
        
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            LOGGER.log(Level.WARNING, "Invalid integer property: " + key + "=" + value);
            return defaultValue;
        }
    }
    
    /**
     * Gets a configuration property as a boolean.
     * 
     * @param key The property key
     * @param defaultValue The default value if the property is not found
     * @return The property value as a boolean, or the default value if not found
     */
    public boolean getBooleanProperty(String key, boolean defaultValue) {
        String value = properties.getProperty(key);
        if (value == null) return defaultValue;
        
        return Boolean.parseBoolean(value);
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
