package com.example.config;

import java.io.File;

import lombok.Data;

/**
 * Represents the command line options for the FIDO2 Client Simulator.
 * This class groups all command line parameters for better organization and maintainability.
 */
@Data
public class CommandOptions {
    private File inputFile;
    private boolean interactive = false;
    private boolean jsonOnly = false;
    private File outputFile;
    private boolean prettyPrint = false;
    private boolean verbose = false;
    private String format = "default";
    private String operation;
    private String jsonInputString;
    private boolean removeNulls = false;
}
