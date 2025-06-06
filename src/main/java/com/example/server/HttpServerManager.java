package com.example.server;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.concurrent.Executors;

import com.example.config.CommandOptions;
import com.example.handlers.CommandHandler;
import com.example.handlers.HandlerFactory;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import lombok.extern.slf4j.Slf4j;

/**
 * HTTP Server manager for FIDO2 Client Simulator.
 * Provides REST endpoints for create and get operations.
 */
@Slf4j
public class HttpServerManager {
    private final HandlerFactory handlerFactory;
    private final CommandOptions options;
    private final ObjectMapper jsonMapper;
    private HttpServer server;
    private final Instant startTime;

    public HttpServerManager(HandlerFactory handlerFactory, CommandOptions options, ObjectMapper jsonMapper) {
        this.handlerFactory = handlerFactory;
        this.options = options;
        this.jsonMapper = jsonMapper;
        this.startTime = Instant.now();
    }

    /**
     * Starts the HTTP server on the specified port.
     * 
     * @param port The port to listen on
     * @throws IOException If the server cannot be started
     */
    public void start(int port) throws IOException {
        server = HttpServer.create(new InetSocketAddress(port), 0);
        
        // Create endpoints
        server.createContext("/create", new Fido2Handler("create"));
        server.createContext("/get", new Fido2Handler("get"));
        server.createContext("/info", new InfoEndpointHandler());
        
        // Use a thread pool executor
        server.setExecutor(Executors.newFixedThreadPool(4));
        
        server.start();
        log.info("FIDO2 HTTP server started on port {}", port);
        log.info("Available endpoints:");
        log.info("  POST /create - Create FIDO2 credentials");
        log.info("  POST /get - Get FIDO2 credentials");
        log.info("  GET /info - Get detailed system and credential information");
    }

    /**
     * Stops the HTTP server.
     */
    public void stop() {
        if (server != null) {
            server.stop(0);
            log.info("HTTP server stopped");
        }
    }

    /**
     * HTTP handler for FIDO2 operations.
     */
    private class Fido2Handler implements HttpHandler {
        private final String operation;

        public Fido2Handler(String operation) {
            this.operation = operation;
        }

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            // Set CORS headers
            exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
            exchange.getResponseHeaders().set("Access-Control-Allow-Methods", "POST, OPTIONS");
            exchange.getResponseHeaders().set("Access-Control-Allow-Headers", "Content-Type");

            if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
                // Handle preflight requests
                exchange.sendResponseHeaders(200, 0);
                exchange.close();
                return;
            }

            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendErrorResponse(exchange, 405, "Method not allowed. Use POST.");
                return;
            }

            try {
                // Read request body
                String requestBody = readRequestBody(exchange.getRequestBody());
                
                if (requestBody == null || requestBody.trim().isEmpty()) {
                    sendErrorResponse(exchange, 400, "Request body is required");
                    return;
                }

                log.debug("Received {} request: {}", operation, requestBody);

                // Create a copy of options for this request
                CommandOptions requestOptions = createRequestOptions();
                requestOptions.setOperation(operation);

                // Create handler and process request
                CommandHandler handler = handlerFactory.createHandler(operation, requestOptions);
                String response = handler.handleRequest(requestBody);

                // Send successful response
                sendJsonResponse(exchange, 200, response);
                
                log.debug("Sent {} response: {}", operation, response);

            } catch (Exception e) {
                log.error("Error processing {} request", operation, e);
                String errorMessage = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
                sendErrorResponse(exchange, 500, "Internal server error: " + errorMessage);
            }
        }

        private String readRequestBody(InputStream inputStream) throws IOException {
            return new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
        }

        private void sendJsonResponse(HttpExchange exchange, int statusCode, String jsonResponse) throws IOException {
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            byte[] responseBytes = jsonResponse.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(statusCode, responseBytes.length);
            
            try (OutputStream outputStream = exchange.getResponseBody()) {
                outputStream.write(responseBytes);
            }
        }

        private void sendErrorResponse(HttpExchange exchange, int statusCode, String errorMessage) throws IOException {
            try {
                String errorJson = jsonMapper.writeValueAsString(new ErrorResponse(errorMessage));
                sendJsonResponse(exchange, statusCode, errorJson);
            } catch (Exception e) {
                // Fallback if JSON serialization fails
                String fallbackError = "{\"error\":\"" + errorMessage.replace("\"", "\\\"") + "\"}";
                sendJsonResponse(exchange, statusCode, fallbackError);
            }
        }

        private CommandOptions createRequestOptions() {
            // Create a copy of the base options for this request
            CommandOptions requestOptions = new CommandOptions();
            requestOptions.setVerbose(options.isVerbose());
            requestOptions.setPrettyPrint(options.isPrettyPrint());
            requestOptions.setRemoveNulls(options.isRemoveNulls());
            requestOptions.setFormat(options.getFormat());
            requestOptions.setJsonOnly(true); // Always JSON-only for HTTP responses
            return requestOptions;
        }
    }

    /**
     * HTTP handler for server information endpoint.
     * Delegates to the existing InfoHandler for detailed system and credential information.
     */
    private class InfoEndpointHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            // Set CORS headers
            exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
            exchange.getResponseHeaders().set("Access-Control-Allow-Methods", "GET, OPTIONS");
            exchange.getResponseHeaders().set("Access-Control-Allow-Headers", "Content-Type");

            if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
                // Handle preflight requests
                exchange.sendResponseHeaders(200, 0);
                exchange.close();
                return;
            }

            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendErrorResponse(exchange, 405, "Method not allowed. Use GET.");
                return;
            }

            try {
                log.debug("Processing info request via InfoHandler");

                // Create a copy of options for this request
                CommandOptions requestOptions = createRequestOptions();
                requestOptions.setOperation("info");

                // Create InfoHandler and process request
                CommandHandler infoHandler = handlerFactory.createHandler("info", requestOptions);
                String response = infoHandler.handleRequest("{}"); // Empty JSON object as input

                // Send successful response
                sendJsonResponse(exchange, 200, response);
                
                log.debug("Sent info response from InfoHandler");

            } catch (Exception e) {
                log.error("Error processing info request", e);
                String errorMessage = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
                sendErrorResponse(exchange, 500, "Internal server error: " + errorMessage);
            }
        }

        private String readRequestBody(InputStream inputStream) throws IOException {
            return new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
        }

        private void sendJsonResponse(HttpExchange exchange, int statusCode, String jsonResponse) throws IOException {
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            byte[] responseBytes = jsonResponse.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(statusCode, responseBytes.length);
            
            try (OutputStream outputStream = exchange.getResponseBody()) {
                outputStream.write(responseBytes);
            }
        }

        private void sendErrorResponse(HttpExchange exchange, int statusCode, String errorMessage) throws IOException {
            try {
                String errorJson = jsonMapper.writeValueAsString(new ErrorResponse(errorMessage));
                sendJsonResponse(exchange, statusCode, errorJson);
            } catch (Exception e) {
                // Fallback if JSON serialization fails
                String fallbackError = "{\"error\":\"" + errorMessage.replace("\"", "\\\"") + "\"}";
                sendJsonResponse(exchange, statusCode, fallbackError);
            }
        }

        private CommandOptions createRequestOptions() {
            // Create a copy of the base options for this request
            CommandOptions requestOptions = new CommandOptions();
            requestOptions.setVerbose(options.isVerbose());
            requestOptions.setPrettyPrint(options.isPrettyPrint());
            requestOptions.setRemoveNulls(options.isRemoveNulls());
            requestOptions.setFormat(options.getFormat());
            requestOptions.setJsonOnly(true); // Always JSON-only for HTTP responses
            return requestOptions;
        }
    }

    /**
     * Simple error response class for JSON serialization.
     */
    public static class ErrorResponse {
        public final String error;

        public ErrorResponse(String error) {
            this.error = error;
        }
    }
} 
