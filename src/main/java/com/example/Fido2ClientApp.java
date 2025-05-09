package com.example;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.io.File;
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
        this.jsonMapper = new ObjectMapper().registerModule(new Jdk8Module());
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
    @Override
    public Integer call() throws Exception {
        String inputJson;
        if (inputFile != null) {
            if (!inputFile.exists()) {
                System.err.println("Input file not found: " + inputFile.getAbsolutePath());
                return 1;
            }
            inputJson = new String(Files.readAllBytes(inputFile.toPath()));
        } else if (jsonInputString != null && !jsonInputString.isEmpty()) {
            inputJson = jsonInputString;
        } else {
            // Read from stdin if neither --file nor JSON string is provided
            System.out.println("Reading JSON input from stdin. Press Ctrl+D (Unix) or Ctrl+Z (Windows) to finish:");
            StringBuilder sb = new StringBuilder();
            try (java.util.Scanner scanner = new java.util.Scanner(System.in)) {
                while (scanner.hasNextLine()) {
                    sb.append(scanner.nextLine()).append("\n");
                }
            }
            inputJson = sb.toString().trim();
            if (inputJson.isEmpty()) {
                System.err.println("No input provided via stdin.");
                return 1;
            }
        }

        try {
            String outputJson;
            if ("create".equalsIgnoreCase(operation)) {
                outputJson = createHandler.handleCreate(inputJson);
                logger.info("Create operation successful. Response:");
                System.out.println(outputJson);
            } else if ("get".equalsIgnoreCase(operation)) {
                // Crear GetHandler aquí, després que Picocli hagi processat el flag --interactive
                GetHandler getHandler = new GetHandler(keyStoreManager, jsonMapper, interactive);
                // Mostrar informació sobre el mode interactiu per a depuració
                if (interactive) {
                    logger.debug("Running in interactive mode");
                }
                outputJson = getHandler.handleGet(inputJson);
                logger.info("Get operation successful. Response:");
                System.out.println(outputJson);
            } else {
                System.err.println("Invalid operation: " + operation + ". Must be 'create' or 'get'.");
                return 1;
            }
        } catch (Exception e) {
            // Mostrar solo el mensaje de error, sin stack trace
            System.err.println("Error during operation '" + operation + "': " + e.getMessage());
            // Registrar el stack trace en el log para depuración, pero no mostrarlo al usuario
            logger.debug("Stack trace:", e);
            return 1;
        }
        return 0;
    }

    /**
     * Main method. Runs the CLI app.
     * @param args Command-line arguments
     */
    public static void main(String[] args) {
        int exitCode = new CommandLine(new Fido2ClientApp()).execute(args);
        System.exit(exitCode);
    }
}
