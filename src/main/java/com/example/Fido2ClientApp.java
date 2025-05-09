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
public class Fido2ClientApp implements Callable<Integer> {
    private static final Logger logger = LoggerFactory.getLogger(Fido2ClientApp.class);

    private final KeyStoreManager keyStoreManager;
    private final ObjectMapper jsonMapper;
    private final CreateHandler createHandler;
    private final GetHandler getHandler;

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
        this.keyStoreManager = new KeyStoreManager();
        this.jsonMapper = new ObjectMapper().registerModule(new Jdk8Module());
        this.createHandler = new CreateHandler(keyStoreManager, jsonMapper);
        this.getHandler = new GetHandler(keyStoreManager, jsonMapper, interactive);
    }

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
                outputJson = getHandler.handleGet(inputJson);
                logger.info("Get operation successful. Response:");
                System.out.println(outputJson);
            } else {
                System.err.println("Invalid operation: " + operation + ". Must be 'create' or 'get'.");
                return 1;
            }
        } catch (Exception e) {
            System.err.println("Error during operation '" + operation + "': " + e.getMessage());
            e.printStackTrace(System.err);
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
