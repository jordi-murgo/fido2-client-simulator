package com.example;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.concurrent.Callable;

import com.example.config.CommandOptions;
import com.example.handlers.CommandHandler;
import com.example.handlers.HandlerFactory;
import com.example.storage.CredentialStore;
import com.example.storage.KeyStoreManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

/**
 * Main CLI entrypoint for the FIDO2 client simulator.
 * Supports 'create', 'get', and 'info' operations via Picocli.
 */
@Command(name = "fido2-client", mixinStandardHelpOptions = true, version = "FIDO2 Client Simulator 1.1",
        description = "Simulates FIDO2 client operations (create/get/info).")
/**
 * Main entry point for the FIDO2 Client Simulator application.
 * <p>
 * This class provides a command-line interface for simulating FIDO2 registration and authentication flows.
 * It manages the creation and retrieval of credentials, handles user and RP information, and provides
 * clear error messages for a better user experience. Stack traces are logged at debug level, but not displayed
 * to the user, ensuring a clean and professional output. Added support for the 'info' operation to display
 * stored credentials and metadata.
 * </p>
 *
 * Usage examples:
 * <pre>
 *   java -jar fido2-client-simulator.jar create -i create_options.json
 *   java -jar fido2-client-simulator.jar get -i get_options.json
 *   java -jar fido2-client-simulator.jar create -i create_options.json --json-only
 *   java -jar fido2-client-simulator.jar get -i get_options.json --output result.json
 *   java -jar fido2-client-simulator.jar info --pretty --verbose
 * </pre>
 *
 * Dependencies:
 * <ul>
 *   <li>Jackson (JSON/CBOR parsing)</li>
 *   <li>BouncyCastle (crypto)</li>
 *   <li>Yubico WebAuthn libraries</li>
 *   <li>Picocli (CLI parser)</li>
 * </ul>
 *
 * @author jpmo
 * @since 2025-05-09
 */
public class Fido2ClientApp implements Callable<Integer> {
    private static final Logger logger = LoggerFactory.getLogger(Fido2ClientApp.class);

    private final CommandOptions options = new CommandOptions();
    private CredentialStore credentialStore;
    private ObjectMapper jsonMapper;
    private HandlerFactory handlerFactory;
    
    // Picocli setters for command line options
    @Option(names = {"-i", "--input"}, description = "Path to the JSON input file containing options.")
    public void setInputFile(File inputFile) {
        options.setInputFile(inputFile);
    }

    @Option(names = {"--interactive"}, description = "Prompt for credential selection if multiple exist (get only)")
    public void setInteractive(boolean interactive) {
        options.setInteractive(interactive);
    }

    @Option(names = {"--json-only"}, description = "Output only the JSON response without any log messages")
    public void setJsonOnly(boolean jsonOnly) {
        options.setJsonOnly(jsonOnly);
    }
    
    @Option(names = {"-o", "--output"}, description = "Path to save the JSON output to a file")
    public void setOutputFile(File outputFile) {
        options.setOutputFile(outputFile);
    }
    
    @Option(names = {"--pretty"}, description = "Format the JSON output with indentation for better readability")
    public void setPrettyPrint(boolean prettyPrint) {
        options.setPrettyPrint(prettyPrint);
    }
    
    @Option(names = {"--verbose"}, description = "Enable verbose output with detailed logging")
    public void setVerbose(boolean verbose) {
        options.setVerbose(verbose);
    }

    @Option(names = {"--format"}, description = "Output format for binary fields: base64url (default), base64, bytes")
    public void setFormat(String format) {
        options.setFormat(format);
    }

    @Parameters(index = "0", description = "The operation to perform: 'create', 'get', or 'info'.")
    public void setOperation(String operation) {
        options.setOperation(operation);
    }

    @Parameters(index = "1", arity = "0..1", description = "JSON string input (alternative to --input).")
    public void setJsonInputString(String jsonInputString) {
        options.setJsonInputString(jsonInputString);
    }
    
    /**
     * Get the command options.
     * @return The command options
     */
    public CommandOptions getOptions() {
        return options;
    }

    /**
     * Constructs the CLI app and initializes handlers and JSON codecs.
     */
    public Fido2ClientApp() {
        try {
            // Inicializar solo lo necesario, los handlers se crearán cuando se conozca el valor de interactive
            this.credentialStore = new KeyStoreManager();
            this.jsonMapper = new ObjectMapper()
                    .registerModule(new Jdk8Module())
                    .setSerializationInclusion(JsonInclude.Include.NON_NULL); // Exclude null values
            this.handlerFactory = new HandlerFactory(credentialStore, jsonMapper);
        } catch (Exception e) {
            System.err.println("ERROR: Failed to initialize the FIDO2 client: " + e.getMessage());
            // En un entorno de producción, se debe considerar un manejo más robusto
            throw new RuntimeException("Failed to initialize the FIDO2 client", e);
        }
    }

    /**
     * Main execution method for the CLI application.
     * <p>
     * Handles the requested FIDO2 operation (create/get/info) and manages errors.
     * If an error occurs, only a concise message is shown to the user, while the full stack trace
     * is logged at debug level for developers.
     * </p>
     *
     * @return Exit code (0 for success, 1 for error)
     * @throws Exception If an error occurs during processing
     */
    @Override
    public Integer call() throws Exception {
        // Configure logging based on options
        if (options.isVerbose()) {
            System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "DEBUG");
        } else {
            System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "INFO");
        }
        
        // Apply JSON formatting based on options
        jsonMapper.configure(SerializationFeature.INDENT_OUTPUT, options.isPrettyPrint());
        // Exclude null values
        jsonMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
        
        // For info operation, input JSON is optional
        String inputJson = null;
        if (!"info".equalsIgnoreCase(options.getOperation())) {
            // Read input JSON for create/get operations
            inputJson = readInputJson();
            if (inputJson == null) {
                return 1; // Error reading input
            }
        }
        
        try {
            // Process the operation and get the result
            String outputJson = processOperation(inputJson);
            if (outputJson == null) {
                return 1; // Error already reported
            }

            // Save to file if requested
            File outputFile = options.getOutputFile();
            if (outputFile != null) {
                try {
                    // Create parent directories if they don't exist
                    if (outputFile.getParentFile() != null && !outputFile.getParentFile().exists()) {
                        outputFile.getParentFile().mkdirs();
                    }
                    
                    Files.write(outputFile.toPath(), outputJson.getBytes());
                    if (!options.isJsonOnly()) {
                        logger.info("Output saved to: " + outputFile.getAbsolutePath());
                    }
                } catch (IOException e) {
                    reportError("Failed to write output to file: " + e.getMessage(), e);
                    return 1;
                }
            }
            
            // Print to stdout unless output is only to file
            if (outputFile == null || options.isVerbose()) {
                System.out.println(outputJson);
            }
            
            return 0; // Success
        } catch (Exception e) {
            reportError("Error during operation '" + options.getOperation() + "': " + e.getMessage(), e);
            return 1;
        }
    }
    
    /**
     * Read input JSON from file, command line argument, or stdin.
     * 
     * @return The input JSON string, or null if an error occurred
     */
    private String readInputJson() {
        try {
            if (options.getInputFile() != null) {
                if (!options.getInputFile().exists()) {
                    reportError("Input file not found: " + options.getInputFile().getAbsolutePath(), null);
                    return null;
                }
                return new String(Files.readAllBytes(options.getInputFile().toPath()));
            } else if (options.getJsonInputString() != null && !options.getJsonInputString().isEmpty()) {
                return options.getJsonInputString();
            } else {
                // Read from stdin if neither --file nor JSON string is provided
                if (!options.isJsonOnly()) {
                    System.out.println("Reading JSON input from stdin. Press Ctrl+D (Unix) or Ctrl+Z (Windows) to finish:");
                }
                StringBuilder sb = new StringBuilder();
                try (java.util.Scanner scanner = new java.util.Scanner(System.in)) {
                    while (scanner.hasNextLine()) {
                        sb.append(scanner.nextLine()).append("\n");
                    }
                }
                String input = sb.toString().trim();
                if (input.isEmpty()) {
                    reportError("No input provided via stdin.", null);
                    return null;
                }
                return input;
            }
        } catch (Exception e) {
            reportError("Error reading input: " + e.getMessage(), e);
            return null;
        }
    }
    
    /**
     * Process the operation (create, get, or info) with the provided input JSON.
     * 
     * @param inputJson The input JSON string
     * @return The output JSON string, or null if an error occurred
     */
    private String processOperation(String inputJson) {
        try {
            CommandHandler handler = handlerFactory.createHandler(options.getOperation(), options);
            return handler.handleRequest(inputJson != null ? inputJson : "{}");
        } catch (Exception e) {
            String errorMessage = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            reportError("Error processing operation: " + errorMessage, e);
            return null;
        }
    }

    /**
     * Report an error in the appropriate format based on the current mode.
     * 
     * @param message The error message
     * @param e The exception (may be null)
     */
    private void reportError(String message, Exception e) {
        if (!options.isJsonOnly()) {
            System.err.println("ERROR: " + message);
            if (e != null && options.isVerbose()) {
                logger.debug("Stack trace:", e);
            }
        } else {
            // In JSON-only mode, output a JSON error object
            System.out.println("{\"error\":\"" + message.replace("\"", "\\\"") + "\"}");
        }
    }

    /**
     * Main method. Runs the CLI app.
     * 
     * @param args Command-line arguments
     */
    public static void main(String[] args) {
        // Configure the command line with better error handling and help formatting
        Fido2ClientApp app = new Fido2ClientApp();
        CommandLine cmd = new CommandLine(app)
                .setUsageHelpAutoWidth(true)
                .setCaseInsensitiveEnumValuesAllowed(true)
                .setExpandAtFiles(true);
        
        // Execute the command and exit with the appropriate code
        int exitCode = cmd.execute(args);
        System.exit(exitCode);
    }
}
