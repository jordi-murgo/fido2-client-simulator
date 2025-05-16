package com.example.config;

import java.io.File;

/**
 * Represents the command line options for the FIDO2 Client Simulator.
 * This class groups all command line parameters for better organization and maintainability.
 */
public class CommandOptions {
    private File inputFile;
    private boolean interactive = false;
    private boolean jsonOnly = false;
    private File outputFile;
    private boolean prettyPrint = false;
    private boolean verbose = false;
    private String format = "base64url";
    private String operation;
    private String jsonInputString;

    // Getters and setters for all fields
    public File getInputFile() { return inputFile; }
    public void setInputFile(File inputFile) { this.inputFile = inputFile; }
    
    public boolean isInteractive() { return interactive; }
    public void setInteractive(boolean interactive) { this.interactive = interactive; }
    
    public boolean isJsonOnly() { return jsonOnly; }
    public void setJsonOnly(boolean jsonOnly) { this.jsonOnly = jsonOnly; }
    
    public File getOutputFile() { return outputFile; }
    public void setOutputFile(File outputFile) { this.outputFile = outputFile; }
    
    public boolean isPrettyPrint() { return prettyPrint; }
    public void setPrettyPrint(boolean prettyPrint) { this.prettyPrint = prettyPrint; }
    
    public boolean isVerbose() { return verbose; }
    public void setVerbose(boolean verbose) { this.verbose = verbose; }
    
    public String getFormat() { return format; }
    public void setFormat(String format) { this.format = format; }
    
    public String getOperation() { return operation; }
    public void setOperation(String operation) { this.operation = operation; }
    
    public String getJsonInputString() { return jsonInputString; }
    public void setJsonInputString(String jsonInputString) { this.jsonInputString = jsonInputString; }
}
