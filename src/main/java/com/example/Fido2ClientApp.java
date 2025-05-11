package com.example;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.concurrent.Callable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Main CLI entrypoint for the FIDO2 client simulator.
 * Supports 'create' and 'get' operations via Picocli.
 */
@Command(name = "fido2-client", mixinStandardHelpOptions = true, version = "FIDO2 Client Sim 1.0",
        description = "Simulates FIDO2 client operations (create/get).")
/**
 * Main entry point for the FIDO2 Client Simulator application.
 * <p>
 * This class provides a command-line interface for simulating FIDO2 registration and authentication flows.
 * It manages the creation and retrieval of credentials, handles user and RP information, and provides
 * clear error messages for a better user experience. Stack traces are logged at debug level, but not displayed
 * to the user, ensuring a clean and professional output.
 * </p>
 *
 * Usage examples:
 * <pre>
 *   java -jar fido2-client-simulator.jar create -f create_options.json
 *   java -jar fido2-client-simulator.jar get -f get_options.json
 *   java -jar fido2-client-simulator.jar create -f create_options.json --json-only
 *   java -jar fido2-client-simulator.jar get -f get_options.json --output result.json
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

    private KeyStoreManager keyStoreManager;
    private ObjectMapper jsonMapper;
    private CreateHandler createHandler;
    // GetHandler es crearà al mètode call() quan es conegui el valor d'interactive

    @Option(names = {"-f", "--file"}, description = "Path to the JSON input file containing options.")
    File inputFile;

    @Option(names = {"--interactive"}, description = "Prompt for credential selection if multiple exist (get only)")
    boolean interactive = false;

    @Option(names = {"--json-only"}, description = "Output only the JSON response without any log messages")
    boolean jsonOnly = false;
    
    @Option(names = {"-o", "--output"}, description = "Path to save the JSON output to a file")
    File outputFile;
    
    @Option(names = {"--pretty"}, description = "Format the JSON output with indentation for better readability")
    boolean prettyPrint = false;
    
    @Option(names = {"--verbose"}, description = "Enable verbose output with detailed logging")
    boolean verbose = false;

    @Parameters(index = "0", description = "The operation to perform: 'create' or 'get'.")
    private String operation;

    @Parameters(index = "1", arity = "0..1", description = "JSON string input (alternative to --file).")
    private String jsonInputString;

    /**
     * Constructs the CLI app and initializes handlers and JSON codecs.
     */
    public Fido2ClientApp() {
        // Inicialitzar només el necessari, GetHandler es crearà quan es conegui el valor d'interactive
        this.keyStoreManager = new KeyStoreManager();
        this.jsonMapper = new ObjectMapper()
                .registerModule(new Jdk8Module())
                .configure(SerializationFeature.INDENT_OUTPUT, true); // Enable pretty printing by default
        this.createHandler = new CreateHandler(keyStoreManager, jsonMapper);
    }

    /**
     * Main execution method for the CLI application.
     * <p>
     * Handles the requested FIDO2 operation (create/get) and manages errors.
     * If an error occurs, only a concise message is shown to the user, while the full stack trace
     * is logged at debug level for developers. This ensures a clean user experience and easier debugging.
     * </p>
     *
     * @return exit code (0 for success, 1 for error)
     */
    /**
     * Process the input JSON and execute the requested FIDO2 operation.
     * 
     * @return Exit code (0 for success, 1 for error)
     * @throws Exception If an error occurs during processing
     */
    @Override
    public Integer call() throws Exception {
        // Configure logging verbosity
        if (verbose && !jsonOnly) {
            // Enable more detailed logging when verbose mode is active
            System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "DEBUG");
        } else if (jsonOnly) {
            // Disable all logging in JSON-only mode
            System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "OFF");
        }
        
        // Read input JSON from file, command line, or stdin
        String inputJson = readInputJson();
        if (inputJson == null) {
            return 1; // Error already reported
        }
        
        try {
            // Process the operation and get the result
            String outputJson = processOperation(inputJson);
            if (outputJson == null) {
                return 1; // Error already reported
            }
            
            // Format the output if needed
            if (prettyPrint && !outputJson.trim().startsWith("{")) {
                // Only try to pretty-print if it's not already formatted and looks like JSON
                try {
                    Object json = jsonMapper.readValue(outputJson, Object.class);
                    outputJson = jsonMapper.writerWithDefaultPrettyPrinter().writeValueAsString(json);
                } catch (Exception e) {
                    // If pretty printing fails, just use the original output
                    if (verbose && !jsonOnly) {
                        logger.debug("Failed to pretty-print JSON output", e);
                    }
                }
            }
            
            // Save to file if requested
            if (outputFile != null) {
                try {
                    // Create parent directories if they don't exist
                    if (outputFile.getParentFile() != null && !outputFile.getParentFile().exists()) {
                        outputFile.getParentFile().mkdirs();
                    }
                    
                    Files.write(outputFile.toPath(), outputJson.getBytes());
                    if (!jsonOnly) {
                        logger.info("Output saved to: " + outputFile.getAbsolutePath());
                    }
                } catch (IOException e) {
                    reportError("Failed to write output to file: " + e.getMessage(), e);
                    return 1;
                }
            }
            
            // Print to stdout unless output is only to file
            if (outputFile == null || verbose) {
                System.out.println(outputJson);
            }
            
            return 0; // Success
        } catch (Exception e) {
            reportError("Error during operation '" + operation + "': " + e.getMessage(), e);
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
            if (inputFile != null) {
                if (!inputFile.exists()) {
                    reportError("Input file not found: " + inputFile.getAbsolutePath(), null);
                    return null;
                }
                return new String(Files.readAllBytes(inputFile.toPath()));
            } else if (jsonInputString != null && !jsonInputString.isEmpty()) {
                return jsonInputString;
            } else {
                // Read from stdin if neither --file nor JSON string is provided
                if (!jsonOnly) {
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
     * Process the operation (create or get) with the provided input JSON.
     * 
     * @param inputJson The input JSON string
     * @return The output JSON string, or null if an error occurred
     */
    private String processOperation(String inputJson) {
        try {
            if ("create".equalsIgnoreCase(operation)) {
                String result = createHandler.handleCreate(inputJson);
                if (!jsonOnly && verbose) {
                    logger.info("Create operation successful.");
                }
                return result;
            } else if ("get".equalsIgnoreCase(operation)) {
                // Create GetHandler here, after Picocli has processed the interactive flag
                GetHandler getHandler = new GetHandler(keyStoreManager, jsonMapper, interactive);
                if (interactive && verbose && !jsonOnly) {
                    logger.debug("Running in interactive mode");
                }
                String result = getHandler.handleGet(inputJson);
                if (!jsonOnly && verbose) {
                    logger.info("Get operation successful.");
                }
                return result;
            } else {
                reportError("Invalid operation: " + operation + ". Must be 'create' or 'get'.", null);
                return null;
            }
        } catch (Exception e) {
            reportError("Error processing operation: " + e.getMessage(), e);
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
        if (!jsonOnly) {
            System.err.println("ERROR: " + message);
            if (e != null && verbose) {
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
        CommandLine cmd = new CommandLine(new Fido2ClientApp())
                .setUsageHelpAutoWidth(true)
                .setCaseInsensitiveEnumValuesAllowed(true)
                .setExpandAtFiles(true);
        
        // Execute the command and exit with the appropriate code
        int exitCode = cmd.execute(args);
        System.exit(exitCode);
    }
}
