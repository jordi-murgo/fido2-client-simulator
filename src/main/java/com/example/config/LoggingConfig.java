package com.example.config;

import java.util.logging.ConsoleHandler;
import java.util.logging.Level;
import java.util.logging.Logger;

public class LoggingConfig {
    private static boolean configured = false;
    
    public static synchronized void configure(boolean verbose) {
        if (configured) {
            return;
        }
        
        // Reset log levels
        Logger rootLogger = Logger.getLogger("");
        rootLogger.setLevel(Level.INFO);
        
        // Remove all existing handlers
        for (java.util.logging.Handler handler : rootLogger.getHandlers()) {
            rootLogger.removeHandler(handler);
        }
        
        // Create and configure console handler
        ConsoleHandler consoleHandler = new ConsoleHandler();
        consoleHandler.setLevel(verbose ? Level.FINE : Level.INFO);
        
        // Add handler to root logger
        rootLogger.addHandler(consoleHandler);
        rootLogger.setLevel(consoleHandler.getLevel());
        
        // Disable parent handlers to prevent duplicate logging
        rootLogger.setUseParentHandlers(false);
        
        configured = true;
    }
}
