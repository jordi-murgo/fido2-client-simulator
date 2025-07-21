# FIDO2 Client Simulator

A Java command-line application that simulates a FIDO2 authenticator for registration (`create`) and authentication (`get`) flows, with enhanced debugging and interoperability features. Designed with modern architectural patterns and SOLID principles.

**Author:** Jordi Murgo (jordi.murgo@gmail.com)

## Table of Contents
- [Quick Start](#quick-start)
- [Features](#features)
- [CLI Reference](#cli-reference)
- [Usage Examples](#usage-examples)
- [Advanced Usage](#advanced-usage)
- [Configuration](#configuration)
- [Architecture](#architecture)
- [WebAuthn.io Integration Scripts](#webauthnio-integration-scripts)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [Changelog](#changelog)
- [License](#license)

## Quick Start

### Prerequisites
- Java 11 or newer
- Maven

### Build & Run
```bash
# Build the project
mvn clean package

# Display information about the current credentials
java -jar target/fido2-client-simulator-1.1-SNAPSHOT.jar info --pretty

# Create a sample credential (using example file)
java -jar target/fido2-client-simulator-1.1-SNAPSHOT.jar create --input create_options.json --pretty
```

## Features

### Core Functionality
- Simulates `navigator.credentials.create()` and `navigator.credentials.get()`
- Input: JSON for `PublicKeyCredentialCreationOptions` (create) or `PublicKeyCredentialRequestOptions` (get)
- Output: JSON representing the FIDO2 `PublicKeyCredential` response

### Design Principles
- **SOLID architecture** with clean separation of concerns
- **Modern functional programming** with Optional, Stream API and lambdas
- Robust validation with defensive approach and elegant exception handling
- Structured logging with appropriate levels

### Advanced Features
- Enhanced metadata storage in JSON format with rich credential information
- PEM-encoded public key storage for improved interoperability
- Detailed attestation and authenticator data decoding for debugging
- Save output directly to file with `--output` option
- Pretty-print JSON output with `--pretty` option
- Detailed logging with `--verbose` option
- Clean JSON-only output with `--json-only` option for scripting

### Technologies
- **Key storage**: Java KeyStore (PKCS12) for secure credential operations
- **Cryptography**: BouncyCastle and Yubico's WebAuthn libraries
- **JSON Processing**: Jackson with CBOR support and custom deserializers
- **Codificación**: Soporte para Base64, Base64URL y formatos binarios
- **CLI**: Picocli for command-line processing
- **Logging**: SLF4J con implementación Logback

## CLI Reference

### Command Line Options

| Category           | Option               | Short | Values                  | Description |
|--------------------|----------------------|-------|-------------------------|-------------|
| **Input/Output**   | `--input <FILE>`     | `-i`  | File path               | Specify input file containing JSON options |
|                    | `--output <FILE>`    | `-o`  | File path               | Save output to specified file |
| **Formatting**     | `--format <FORMAT>`  | `-f`  | default,bytes,ints,ping | Configure binary data encoding format |
|                    | `--pretty`           |       |                         | Pretty-print JSON output with indentation |
|                    | `--json-only`        |       |                         | Output only raw JSON response |
|                    | `--remove-nulls`     |       |                         | Remove null values from JSON output |
| **Debugging**      | `--verbose`          |       |                         | Enable detailed logging and debug output |
| **Interaction**    | `--interactive`      |       |                         | Enable interactive credential selection (get operation) |
| **Server Mode**    | `--listen <PORT>`    |       | 0-65535                 | Start HTTP server on specified port |
| **General**        | `--help`             | `-h`  |                         | Show help message and exit |
|                    | `--version`          | `-V`  |                         | Print version information and exit |

### Operations

| Operation | Description |
|-----------|-------------|
| `create` | Simulates credential creation (registration) |
| `get` | Simulates credential usage (authentication) |
| `info` | Displays information about stored credentials |

## Usage Examples

### Input Methods

You can provide input to the CLI in three ways:

1. **Input file** (recommended for large/complex JSON):
   ```bash
   java -jar target/fido2-client-simulator-1.1-SNAPSHOT.jar <create|get> --input <input.json>
   ```

2. **Direct JSON string argument**:
   ```bash
   java -jar target/fido2-client-simulator-1.1-SNAPSHOT.jar <create|get> '{JSON data...}'
   ```

3. **Standard input (pipe or keyboard)**:
   ```bash
   cat input.json | java -jar target/fido2-client-simulator-1.1-SNAPSHOT.jar <create|get>
   ```

### Registration (`create`)

#### Basic Example
```bash
java -jar target/fido2-client-simulator-1.1-SNAPSHOT.jar create -i create_options.json -o response.json
```

#### Example with Custom Challenge and Format
```bash
java -jar target/fido2-client-simulator-1.1-SNAPSHOT.jar create -i create_options.json -f bytes --pretty
```

#### Example Input JSON
```json
{
  "challenge": "TEmqTQU6DhV2SaO0YFTM15KsqWyiFqpjHWa43HT7wBkKLNVQQttG5ADyRXjR8GZNFl8kexjNUKYwl6JF2MxHDA",
  "rp": {
    "name": "Example RP",
    "id": "example.com"
  },
  "user": {
    "id": "user123",
    "name": "user@example.com",
    "displayName": "Example User"
  },
  "pubKeyCredParams": [
    {"type": "public-key", "alg": -7},
    {"type": "public-key", "alg": -257}
  ],
  "timeout": 60000,
  "attestation": "direct",
  "authenticatorSelection": {
    "authenticatorAttachment": "platform",
    "requireResidentKey": false,
    "residentKey": "preferred",
    "userVerification": "preferred"
  }
}
```

### Authentication (`get`)

```bash
java -jar target/fido2-client-simulator-1.1-SNAPSHOT.jar get --input get_options.json
```

### Credential Store Information (`info`)

```bash
java -jar target/fido2-client-simulator-1.1-SNAPSHOT.jar info --pretty
```

## Debugging y Depuración

### Niveles de Log

Los niveles de log se pueden configurar en `logback.xml`. Los niveles disponibles son:
- `TRACE`: Muestra toda la información, incluyendo el procesamiento detallado de desafíos
- `DEBUG`: Información detallada de depuración
- `INFO`: Información general del flujo de la aplicación
- `WARN`: Advertencias de posibles problemas
- `ERROR`: Errores que requieren atención

### Ejemplo de Salida de Depuración

```
TRACE - Deserializando campo 'challenge' desde string base64url (88 caracteres)
DEBUG - Challenge bytes (hex): 4c49efbfbd4d053a0e157649...
DEBUG - Challenge base64url: TEnvv71NBToOFXZJ77-977-9YFTvv73Xku...
```

## Advanced Usage

### Output Formatting and File Redirection

#### Pretty-Print JSON Output
```bash
java -jar target/fido2-client-simulator-1.1-SNAPSHOT.jar create --input create_options.json --pretty
```

#### Save Output to File
```bash
java -jar target/fido2-client-simulator-1.1-SNAPSHOT.jar create --input create_options.json --output response.json
```

#### JSON-Only Response (for Scripting)
```bash
java -jar target/fido2-client-simulator-1.1-SNAPSHOT.jar create --input create_options.json --json-only
```

### Detailed Logging with Verbose Mode
```bash
java -jar target/fido2-client-simulator-1.1-SNAPSHOT.jar info --verbose --pretty
```

### Base64-Encoded Input Support
You can provide the input JSON as Base64-encoded content:
```bash
base64 -i create_options.json | java -jar target/fido2-client-simulator-1.1-SNAPSHOT.jar create
```

### Interactive Credential Selection
When using `get` with multiple available credentials:
```bash
java -jar target/fido2-client-simulator-1.1-SNAPSHOT.jar get --input get_options.json --interactive
```

### Attestation Object Decoding
During credential creation, the attestation object is automatically decoded and displayed.

### Output Formats

The simulator supports different output formats for binary data in the response. You can specify the format using the `--format` or `-f` option:

```bash
java -jar target/fido2-client-simulator-1.1-SNAPSHOT.jar create -i create_options.json -f bytes
```

#### Available Formats

| Format | Description |
|--------|-------------|
| `default` | Uses base64url for all binary fields |
| `bytes` | Outputs binary data as arrays of signed bytes (-128 to 127) |
| `ints` | Outputs binary data as arrays of unsigned integers (0-255) |
| `ping` | Optimized format for Ping Identity compatibility |

#### Format Configuration

Formats are defined in `src/main/resources/configuration.yaml`. Each format specifies how different fields should be encoded:

- `base64`: Standard Base64 encoding (with +/=)
- `base64url`: URL-safe Base64 encoding (with -_)
- `byteArray`: Array of signed bytes (-128 to 127)
- `intArray`: Array of unsigned integers (0-255)
- `string`: Try to decode as UTF-8 text (falls back to base64url if not valid)
- `number`: mantains the number as it is
- `object`: mantains the object as it is
- `null`: Sets the field to null (type `'null'` in the configuration)
- `remove`: Exclude the field from output

### Configuration

The simulator uses a YAML configuration file for format definitions and other settings. The default configuration is loaded from the classpath at `configuration.yaml`.

#### Configuration File Locations
The configuration is loaded from the following locations in order of precedence:

1. File specified by `FIDO2_CONFIG` environment variable
2. `config/configuration.yaml` in the current directory
3. `configuration.yaml` in the current directory
4. Default configuration from classpath

#### Example Configuration

```yaml
# Keystore settings
keystore:
  path: fido2_keystore.p12
  password: changeme
  metadataPath: fido2_keystore_metadata.json

# Logging level (DEBUG, INFO, WARN, ERROR)
logLevel: INFO

# Output formats configuration
formats:
  # Default format - uses base64url for binary fields (WebAuthn standard)
  default:
    id: base64url
    rawId: base64url
    authenticatorData: base64url
    clientDataJSON: base64url
    signature: base64url
    userHandle: base64url
    attestationObject: base64url
    publicKey: base64url
    
  # Bytes format - outputs binary data as signed byte arrays
  bytes:
    id: base64url
    rawId: byteArray
    authenticatorData: byteArray
    clientDataJSON: string
    signature: byteArray
    userHandle: base64url
    attestationObject: byteArray
    publicKey: byteArray
    
  # Ints format - outputs binary data as unsigned integers
  ints:
    id: base64url
    rawId: intArray
    authenticatorData: intArray
    clientDataJSON: string
    signature: intArray
    userHandle: base64url
    attestationObject: intArray
    publicKey: intArray
    
  # Ping format - optimized for Ping Identity compatibility
  ping:
    id: 'null'
    rawId: 'base64url'
    clientDataJSON: 'string'
    attestationObject: 'byteArray'
    authenticatorData: 'byteArray'
    publicKey: 'null'
    publicKeyAlgorithm: 'null'
    signature: 'byteArray'
    userHandle: 'null'
```

### Files Created

- `fido2_keystore.p12`: Stores credential private keys in PKCS12 format
- `fido2_keystore_metadata.json`: Stores credential metadata including:
  - Registration response JSON
  - RP (Relying Party) information
  - User information
  - Public key details
  - Creation timestamp
  - Credential ID and other metadata

## Architecture

### Component Diagram

```mermaid
graph TD
    CLI[CLI - Command Line Interface] --> App[Fido2ClientApp]
    App --> Factory[HandlerFactory]
    Factory --> CreateH[CreateHandler]
    Factory --> GetH[GetHandler]
    Factory --> InfoH[InfoHandler]
    CreateH --> CredStore[CredentialStore]
    GetH --> CredStore
    InfoH --> CredStore
    CredStore --> KeyStore[KeyStoreManager]
    KeyStore --> PKCS12[(PKCS12 KeyStore)]
    KeyStore --> MetaData[(JSON Metadata)]
    
    classDef interface fill:#f9f,stroke:#333,stroke-dasharray: 5 5;
    classDef implementation fill:#9cf,stroke:#333;
    classDef data fill:#fcf,stroke:#333;
    
    class CredStore interface;
    class KeyStore,CreateH,GetH,InfoH,Factory implementation;
    class PKCS12,MetaData data;
    class CreateH,GetH,InfoH implements_CommandHandler;
    
    %% Note: All handlers now implement CommandHandler interface
    %% InfoHandler is now shown in the diagram as well.
```

### Implemented Design Patterns

#### 1. Repository Pattern (CredentialStore)
`CredentialStore` acts as an abstract repository for credential storage operations, decoupling business logic from the persistence mechanism.

#### 2. Factory Pattern (HandlerFactory)
Implementation of the Factory pattern for creating specific handlers.

#### 3. Strategy Pattern (Handlers)
The `CreateHandler`, `GetHandler`, and `InfoHandler` handlers implement different strategies for processing FIDO2 operations, sharing the common `CommandHandler` interface.

#### 4. Functional Programming and Optional
Use of modern functional programming techniques for more concise and safer code.

### Architecture Benefits

1. **Testability**: The use of interfaces facilitates testing with mocks.
2. **Extensibility**: New storage types can implement `CredentialStore`.
3. **Maintainability**: Clear separation of responsibilities.
4. **Security**: Robust exception handling and input validation.
5. **Evolution**: Facilitates the incorporation of new features without modifying existing code.

## WebAuthn.io Integration Scripts

The project includes two example scripts that demonstrate how to use FIDO2 Client Simulator with the WebAuthn.io demo site.

### WebAuthn.io Integration Diagrams

#### Registration Flow Sequence Diagram

```mermaid
sequenceDiagram
    participant Simulator as fido2-client-simulator.jar
    participant Script as webauthn-io-tutorial-registration.sh
    participant Curl as curl
    participant WebAuthn as https://webauthn.io

    activate Script
    Note over Script: Start
    
    Script->>Curl: Request registration options
    Curl->>WebAuthn: POST /registration/options
    WebAuthn-->>Curl: Return PublicKeyCredentialCreationOptions
    Curl-->>Script: Save options to file
    
    Script->>Simulator: Pass options to simulator
    Note right of Simulator: Generate key pair & attestation
    Simulator-->>Script: Return credential response
    
    Script->>Curl: Submit credential for verification
    Curl->>WebAuthn: POST /registration/verification
    WebAuthn-->>Curl: Verify and return result
    Curl-->>Script: Report verification status
    
    Note over Script: Save all data for analysis
```

#### Authentication Flow Sequence Diagram

```mermaid
sequenceDiagram
    participant Simulator as fido2-client-simulator.jar
    participant Script as webauthn-io-tutorial-authentication.sh
    participant Curl as curl
    participant WebAuthn as https://webauthn.io
    
    activate Script
    Note over Script: Start
    
    Script->>Curl: Request authentication options
    Curl->>WebAuthn: POST /authentication/options
    WebAuthn-->>Curl: Return PublicKeyCredentialRequestOptions
    Curl-->>Script: Save options to file
    
    Script->>Simulator: Pass options to simulator
    Note right of Simulator: Load credential & generate assertion
    Simulator-->>Script: Return assertion response
    
    Script->>Curl: Submit assertion for verification
    Curl->>WebAuthn: POST /authentication/verification
    WebAuthn-->>Curl: Verify and return result
    Curl-->>Script: Report verification status
    
    Note over Script: Save all data for analysis
```

## Troubleshooting

### Manejo de Desafíos (Challenges)

El simulador maneja automáticamente los desafíos durante el registro y autenticación. Si encuentras problemas:

1. **Formato del Challenge**:
   - Asegúrate de que el challenge esté en formato Base64URL
   - El simulador intentará decodificar automáticamente si está en otro formato

2. **Verificación del Challenge**:
   - Durante el registro, se valida que el challenge no se modifique
   - Se incluyen logs detallados con el prefijo `ByteArrayDeserializer` para depuración

3. **Logs de Depuración**:
   - Usa `--verbose` para ver información detallada del procesamiento
   - Los desafíos se registran en formato hexadecimal para facilitar la comparación

### Common Issues

- **KeyStore errors**: Ensure you have proper write permissions to the keystore directory.
- **Java version compatibility**: Confirm you're using Java 11 or newer.
- **JSON parsing errors**: Check for syntax errors in your input JSON files.
- **Missing credentials**: Use the `info` command to check available credentials.

## HTTP Server Mode

The FIDO2 Client Simulator can also run as an HTTP server, exposing REST endpoints for FIDO2 operations. This mode is useful for integration with web applications and automated testing.

### Starting the Server

```bash
java -jar target/fido2-client-simulator-1.3.0-SNAPSHOT.jar --listen 8080
```

### Available Endpoints

- **POST /create** - Create FIDO2 credentials
- **POST /get** - Authenticate with FIDO2 credentials  
- **GET /info** - Get server and credential information

### Query Parameters

All endpoints support optional query parameters for customizing output format and behavior:

- `format`: Output format for binary fields (`default`, `bytes`, `ints`, `ping`)
- `pretty`: Pretty-print JSON responses (`true`/`false`)
- `verbose`: Enable detailed logging (`true`/`false`)
- `remove-nulls`: Remove null values from responses (`true`/`false`)

### Examples

```bash
# Create credential with pretty-printed output
curl -X POST "http://localhost:8080/create?pretty=true" \
  -H "Content-Type: application/json" \
  -d '{
    "rp": {"name": "Test RP", "id": "localhost"},
    "user": {"name": "testuser", "displayName": "Test User", "id": "dGVzdA"},
    "challenge": "AAAAAAAAAAAAAAAAAAAAAA",
    "pubKeyCredParams": [{"type": "public-key", "alg": -7}]
  }'

# Get server info with bytes format
curl "http://localhost:8080/info?format=bytes&pretty=true"

# Authenticate with ping format
curl -X POST "http://localhost:8080/get?format=ping&pretty=true" \
  -H "Content-Type: application/json" \
  -d '{
    "challenge": "BBBBBBBBBBBBBBBBBBBBBB",
    "rpId": "localhost",
    "userVerification": "discouraged"
  }'
```

### Features

- **CORS Support**: Includes proper CORS headers for web integration
- **Error Handling**: Consistent JSON error responses
- **Format Flexibility**: Multiple output formats for different client needs
- **Query Parameter Override**: Runtime configuration via URL parameters

See [HTTP_SERVER_USAGE.md](HTTP_SERVER_USAGE.md) for detailed documentation and examples.

### Diagnostic Tips

1. Use `--verbose` to get detailed logging and error information.
2. Examine the output of `info --verbose` to check credential status.
3. For attestation issues, review the decoded attestation object details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Changelog

### [1.3.0] - 2025-05-20
- **Improved**: Dependency management to avoid downloading SNAPSHOTs from nexus mirror
- **Enhanced**: Simplified challenge handling during registration process

### [1.2.0] - 2025-05-19
- **Improved**: Better handling of challenges during registration
- **New**: Enhanced Base64 encoding/decoding utilities
- **Debug**: More detailed logging for challenge tracking
- **Performance**: JSON processing optimization

### [1.1.0] - 2025-05-15
- Added support for `CommandHandler` interface replacing `CredentialHandler`
- Enhanced `info` command with detailed system configuration output
- Changed --file option to --input for consistency
- Improved error handling and documentation

### v1.0
- Initial release with core FIDO2 functionality
- Support for registration and authentication

## License

© 2025 Jordi Murgo (jordi.murgo@gmail.com). FIDO2 Client Simulator. MIT License.
