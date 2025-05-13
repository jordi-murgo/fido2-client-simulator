# FIDO2 Client Simulator

A Java command-line application that simulates a FIDO2 authenticator for registration (`create`) and authentication (`get`) flows, with enhanced debugging and interoperability features. Designed with modern architectural patterns and SOLID principles.

**Author:** Jordi Murgo (jordi.murgo@gmail.com)

## Features

### Core Functionality
- Simulates `navigator.credentials.create()` and `navigator.credentials.get()`
- Input: JSON for `PublicKeyCredentialCreationOptions` (create) or `PublicKeyCredentialRequestOptions` (get)
- Output: JSON representing the FIDO2 `PublicKeyCredential` response

### Architecture and Design
- **Layered architecture** with clear separation of concerns
- **Factory Pattern** for credential handler creation
- **Interfaces** for decoupling (`CredentialStore`) following the Dependency Inversion Principle
- **Modern functional programming** with Optional, Stream API and lambdas
- Robust validation with defensive approach and elegant exception handling
- Structured logging with appropriate levels

### Advanced Features
- Enhanced metadata storage in JSON format with rich credential information
- PEM-encoded public key storage for improved interoperability
- Detailed attestation and authenticator data decoding for debugging
- Save output directly to file with `--output` option
- Pretty-print JSON output with `--pretty` option
- Detailed logging with `--verbose` option (with extended information for `info` command)
- Clean JSON-only output with `--json-only` option for scripting

### Technologies
- **Key storage**: Java KeyStore (PKCS12) for secure credential operations
- **Cryptography**: Uses BouncyCastle and Yubico's WebAuthn libraries
- **JSON**: Uses Jackson with CBOR support
- **CLI**: Uses Picocli for command-line processing

## Build Instructions

1. **Install prerequisites:**
   - Java 11 or newer
   - Maven

2. **Build the project:**
   ```bash
   mvn clean package
   ```
   This will produce a fat JAR at `target/fido2-client-simulator-1.0-SNAPSHOT.jar`.

## CLI Usage

### Command-Line Options

The FIDO2 Client Simulator supports the following command-line options:

| Option | Description |
|--------|-------------|
| `--file`, `-f` | Specify an input file containing JSON options |
| `--output`, `-o` | Save the output to a specified file |
| `--pretty` | Format the JSON output with indentation for better readability |
| `--verbose` | Enable detailed logging and show extended information (particularly useful with `info` operation) |
| `--json-only` | Output only the JSON response (useful for scripting) |
| `--interactive` | Enable interactive credential selection (for `get` operation) |
| `--help` | Show help message |

### Input Methods

You can provide input to the CLI in three ways:

1. **Input file** (recommended for large/complex JSON):
   ```bash
   java -jar target/fido2-client-simulator-1.0-SNAPSHOT.jar <create|get> --file <input.json>
   ```
   Example:
   ```bash
   java -jar target/fido2-client-simulator-1.0-SNAPSHOT.jar create --file create_options.json
   ```

2. **Direct JSON string argument**:
   ```bash
   java -jar target/fido2-client-simulator-1.0-SNAPSHOT.jar <create|get> '{"challenge": "...", ...}'
   ```
   Example:
   ```bash
   java -jar target/fido2-client-simulator-1.0-SNAPSHOT.jar get '{"challenge": "BBBB...", "rpId": "localhost", ...}'
   ```

3. **Standard Input (stdin)** (if neither --file nor JSON string is given):
   ```bash
   java -jar target/fido2-client-simulator-1.0-SNAPSHOT.jar <create|get>
   # Paste or pipe your JSON, then press Ctrl+D (Unix) or Ctrl+Z (Windows) to finish
   ```
   Example:
   ```bash
   echo '{"challenge": "CCCC...", "rpId": "localhost", ...}' | java -jar target/fido2-client-simulator-1.0-SNAPSHOT.jar get
   ```

### Base64-Encoded Input Support

You can also provide the input JSON as Base64-encoded content. The application will automatically attempt to decode Base64 (both standard and URL-safe variants) before processing the JSON:

```bash
# Create a Base64-encoded version of your input file
base64 -i create_options.json | java -jar target/fido2-client-simulator-1.0-SNAPSHOT.jar create
```

This is useful when:
- Working with WebAuthn implementations that encode their options as Base64
- Exchanging options between systems where Base64 encoding is preferred
- Passing complex JSON through environments that might interfere with JSON formatting

The application tries the following decodings in sequence:
1. Base64 URL-safe decoding
2. Standard Base64 decoding
3. Fallback to using the input as-is (plain JSON)

---

### Registration (`create`)

**Example input (`create_options.json`):**
```json
{
  "rp": {
    "name": "My Test RP",
    "id": "localhost"
  },
  "user": {
    "name": "testuser",
    "displayName": "Test User",
    "id": "dGVzdHVzZXJfaWQ="
  },
  "challenge": "AAAAAAAAAAAAAAAAAAAAAA",
  "pubKeyCredParams": [
    { "type": "public-key", "alg": -7 },
    { "type": "public-key", "alg": -257 }
  ],
  "authenticatorSelection": {
    "userVerification": "discouraged"
  },
  "attestation": "packed"
}
```

**Run registration (with file):**
```bash
java -jar target/fido2-client-simulator-1.0-SNAPSHOT.jar create --file create_options.json
```

**Run registration (via stdin):**
```bash
cat create_options.json | java -jar target/fido2-client-simulator-1.0-SNAPSHOT.jar create
```

### Credential Store Information (`info`)

The `info` operation displays information about all credentials stored in the keystore and metadata files:

```bash
java -jar target/fido2-client-simulator-1.0-SNAPSHOT.jar info --pretty
```

To get more detailed information about the credentials, storage, and system configuration, use the `--verbose` option:

```bash
java -jar target/fido2-client-simulator-1.0-SNAPSHOT.jar info --verbose --pretty
```

Example output:

```json
{
  "totalCredentials": 2,
  "relyingParties": [
    "localhost",
    "webauthn.io"
  ],
  "credentials": [
    {
      "id": "81btYVAvQ_q5gTAkOLwVOA",
      "createdAt": "2025-05-13 10:43:58",
      "signCount": 0,
      "relyingParty": {
        "id": "webauthn.io",
        "name": "WebAuthn.io"
      },
      "user": {
        "id": "dXNlcl9pZA",
        "name": "test_user"
      }
    },
    {
      "id": "_U4-UykeRe6TlR2W2bL1Yg",
      "createdAt": "2025-05-12 16:24:33",
      "signCount": 2,
      "relyingParty": {
        "id": "localhost",
        "name": "Test Application"
      },
      "user": {
        "id": "YWJjZGVm",
        "name": "user1",
        "displayName": "User One"
      }
    }
  ]
}
```

Use the `--details` flag to include additional technical information (public key details, storage paths, etc.):

```bash
java -jar target/fido2-client-simulator-1.0-SNAPSHOT.jar info --pretty --details
```

This command is particularly useful for:

- Debugging credential issues
- Verifying which credentials are available for each relying party
- Checking the status of the credential store before operations
- Auditing the credential database

With the `--verbose` option, you'll also see:
- Public key information in PEM format
- Storage configuration details including file paths and last update timestamps
- File status including size and last modified dates
- System information (Java version, OS, etc.)

### Authentication (`get`)

**Example input (`get_options.json`):**
```json
{
  "challenge": "BBBBBBBBBBBBBBBBBBBBBB",
  "rpId": "localhost",
  "allowCredentials": [
    {
      "type": "public-key",
      "id": "<CredentialID-from-create-response>"
    }
  ],
  "userVerification": "discouraged"
}
```

**Run authentication (with file):**
```bash
java -jar target/fido2-client-simulator-1.0-SNAPSHOT.jar get --file get_options.json
```

**Run authentication (direct JSON string):**
```bash
java -jar target/fido2-client-simulator-1.0-SNAPSHOT.jar get '{
  "challenge": "BBBBBBBBBBBBBBBBBBBBBB",
  "rpId": "localhost",
  "allowCredentials": [
    { "type": "public-key", "id": "<CredentialID-from-create-response>" }
  ],
  "userVerification": "discouraged"
}'
```

**Run authentication (stdin):**
```bash
cat get_options.json | java -jar target/fido2-client-simulator-1.0-SNAPSHOT.jar get
```
# or
```bash
java -jar target/fido2-client-simulator-1.0-SNAPSHOT.jar get
# (paste JSON, then Ctrl+D)
```

---

### Arguments Supported by `get` (Authentication)

The `get` command simulates the FIDO2 authentication (assertion) process and supports the following input arguments (as JSON):

- `challenge` (required): Random challenge from the server.
- `rpId` (required): Relying Party identifier (e.g., `localhost`).
- `allowCredentials` (optional): List of credential descriptors to allow. If omitted, all credentials for the given `rpId` are considered.
- `userVerification` (optional): Can be `required`, `preferred`, or `discouraged`.
- `timeout` (optional): Timeout in milliseconds.
- `extensions` (optional): Extensions for additional features (e.g., `{ "uvm": true }`).

#### Credential Selection Logic (when `allowCredentials` is not provided)

When the input JSON for authentication **does not** include `allowCredentials`, the simulator will:

- **Search for all credentials stored for the given `rpId`.**
    - If only one credential exists, it is used automatically.
    - If multiple credentials exist:
        - By default (non-interactive), the first credential is used automatically and a warning is printed to notify the user.
        - If you add `--interactive`, the CLI will prompt you to select which credential to use among those available for the specified `rpId`.

This behavior matches modern authenticator implementations and enables both automated and manual testing workflows.

#### Example: Authentication without `allowCredentials` array

Suppose you have the following input file (`get_options_notcredentials.json`):

```json
{
  "challenge": "BBBBBBBBBBBBBBBBBBBBBB",
  "rpId": "localhost",
  "userVerification": "required",
  "timeout": 60000,
  "extensions": {
    "uvm": true
  }
}
```

You can run the authentication as follows:

```bash
java -jar target/fido2-client-simulator-1.0-SNAPSHOT.jar get --file get_options_notcredentials.json
```

- If only one credential exists for `localhost`, it will be used.
- If multiple credentials exist for `localhost`, the first will be chosen by default, or you can use `--interactive` to select one:

```bash
java -jar target/fido2-client-simulator-1.0-SNAPSHOT.jar get --file get_options_notcredentials.json --interactive
```

#### Enhanced Interactive Credential Selection

When using the `--interactive` flag, the simulator displays a formatted table showing available credentials with user information:

```
[INFO] Multiple credentials found for rpId 'localhost':
--------------------------------------------------------------
  IDX | CREDENTIAL ID                  | USER INFO
--------------------------------------------------------------
  [0] | 50vs7QTXQjWwPKmtRvdUqA         | testuser (Test User)
  [1] | nEb4vWGvTBeRCuwic_BtcA         | testuser (Test User)
  [2] | T4qVPp9NQN6iVX5cCZRgtg         | testuser (Test User)
--------------------------------------------------------------
Select credential index: 2
[INFO] Selected credential: T4qVPp9NQN6iVX5cCZRgtg
```

This enhanced display:
- Shows each credential ID in a readable format (truncated if too long)
- Displays the user name and display name associated with each credential
- Makes it easy to identify the correct credential when multiple are available
- Especially useful in multi-user environments where different users have registered credentials on the same device

You can select the desired credential by entering its index number.

#### Summary Table: Credential Selection

| Scenario                              | Behavior                                                  |
|---------------------------------------|-----------------------------------------------------------|
| `allowCredentials` present            | Only listed credentials are eligible for assertion        |
| `allowCredentials` missing, 1 present | That credential is used automatically                     |
| `allowCredentials` missing, >1 present| First credential used (default), or prompt with `--interactive` |

#### Notes
- The simulator always filters credentials by the provided `rpId`.
- The selection logic is designed for both scripting (automatic) and manual (interactive) use cases.
- For advanced debugging, enable verbose logging or inspect the metadata output for credential details.

**This flexible behavior ensures the simulator is realistic and suitable for both automated CI and manual QA workflows.**

## Files
- `fido2_keystore.p12`: Stores credential private keys in PKCS12 format
- `fido2_metadata.json`: Stores rich credential metadata including:
  - Registration response JSON
  - RP information
  - User information
  - PEM-encoded public key
  - Creation timestamp

## Advanced Features

### Output Formatting and Saving

#### Pretty-Print JSON Output

Use the `--pretty` option to format the JSON output with proper indentation for better readability:

```bash
java -jar target/fido2-client-simulator-1.0-SNAPSHOT.jar create --file create_options.json --pretty
```

This produces nicely formatted JSON that's easier to read and analyze:

```json
{
  "id" : "afdwmPF5T7yBNPUd4DP1Ow",
  "response" : {
    "attestationObject" : "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViUSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAAAAAAAAAAAAAAAAAAAAAAAAAAECC_99reuEKrrQajsYFOtsGlAQIDJiABIVggxzbUxC0ZA_vVO2kz0WqO9SnbbmEaqOvuoy14cyyL3HYiWCAUsdMw3-wlwJP7YoJPXFOoE0d6oGQa1OTHjBJgXiTODg",
    "clientDataJSON" : "ewogICJ0eXBlIiA6ICJ3ZWJhdXRobi5jcmVhdGUiLAogICJjaGFsbGVuZ2UiIDogIlkyaGhiR3hsYm1kbCIsCiAgIm9yaWdpbiIgOiAiaHR0cHM6Ly9sb2NhbGhvc3QiCn0",
    "transports" : [ ]
  },
  "authenticatorAttachment" : null,
  "clientExtensionResults" : {
    "appidExclude" : null,
    "credProps" : null,
    "largeBlob" : null
  },
  "type" : "public-key"
}
```

#### Save Output to File

Use the `--output` (or `-o`) option to save the JSON output directly to a file:

```bash
java -jar target/fido2-client-simulator-1.0-SNAPSHOT.jar create --file create_options.json --output result.json
```

This is particularly useful for:
- Saving results for later analysis
- Integrating with automated testing pipelines
- Creating documentation examples

You can combine this with `--pretty` for nicely formatted saved output:

```bash
java -jar target/fido2-client-simulator-1.0-SNAPSHOT.jar create --file create_options.json --pretty --output result.json
```

#### JSON-Only Mode for Scripting

Use the `--json-only` option to output only the JSON response without any additional logging or information:

```bash
java -jar target/fido2-client-simulator-1.0-SNAPSHOT.jar create --file create_options.json --json-only
```

This is ideal for:
- Scripting and automation
- Piping output to other tools
- CI/CD integration

### Verbose Logging

Enable detailed logging with the `--verbose` option to see more information about the credential creation, assertion process, or stored credentials:

```bash
java -jar target/fido2-client-simulator-1.0-SNAPSHOT.jar get --file get_options.json --verbose
```

Verbose output includes:
- Detailed information about credential selection
- Debugging information for attestation and assertion
- Step-by-step processing information
- Error details when problems occur

Example verbose output:
```
[INFO] Checking 1 credentials from allowCredentials list
[DEBUG] Checking credential #0: U5HoKUR1ToCH1UeXiUXrKA
[INFO] Using credential: U5HoKUR1ToCH1UeXiUXrKA (position 0 in allowCredentials list)
```

For the `info` command, `--verbose` also provides detailed system and configuration information:

```json
{
  "configuration": {
    "storage": {
      "keystorePath": "fido2_keystore.p12",
      "metadataPath": "fido2_metadata.json"
    },
    "timing": {
      "lastKeystoreUpdate": "2025-05-13 11:28:36",
      "lastMetadataUpdate": "2025-05-13 11:29:23"
    },
    "fileStatus": {
      "keystoreExists": true,
      "metadataExists": true,
      "keystoreSize": "1022 bytes",
      "keystoreLastModified": "2025-05-13 11:28:36"
    },
    "system": {
      "javaVersion": "24.0.1",
      "osName": "Mac OS X",
      "currentTime": "2025-05-13 12:10:55"
    }
  }
}
...
```

### PEM-Encoded Public Key Storage
Each credential's public key is stored in standard PEM format (X.509 SubjectPublicKeyInfo) in the metadata, enabling:
- Easy interoperability with other systems and languages
- Direct use for signature verification without accessing the keystore
- Standard format for cryptographic operations

### Configuration File System

The FIDO2 Client Simulator supports external configuration via properties files. This allows you to customize the storage locations and security settings without modifying the code, following the Open/Closed principle.

#### Configuration File Locations

The configuration is loaded from the following locations in order of precedence:

1. Current directory: `fido2_config.properties`
2. User home directory: `~/.fido2/config.properties`
3. System-wide: `/etc/fido2/config.properties`
4. Application classpath (default embedded configuration)

#### Available Configuration Properties

| Property | Description | Default Value |
|----------|-------------|---------------|
| `keystore.path` | Path to the PKCS12 keystore file | `fido2_keystore.p12` |
| `metadata.path` | Path to the JSON metadata file | `fido2_metadata.json` |
| `keystore.password` | Password for the keystore | `fido2simulator` |
| `log.level` | Logging level | `INFO` |

#### Example Configuration File

```properties
# FIDO2 Client Simulator Configuration

# Paths for credential storage
# You can use relative or absolute paths
keystore.path=/secure/path/fido2_keystore.p12
metadata.path=/secure/path/fido2_metadata.json

# Security settings
keystore.password=your_secure_password

# Logging configuration
log.level=INFO
```

A sample configuration file is included as `fido2_config.properties.sample` which you can copy and customize to your needs.

### Attestation Object Decoding
During credential creation, the attestation object is automatically decoded and displayed:
```
=== AttestationObject (decoded) ===
fmt: "none"
authData (base64): [base64-encoded-auth-data]

--- AuthData Structure ---
rpIdHash: [hex-encoded-hash]
flags: 0x45 (UP=1, UV=1, AT=1, ED=0)
signCount: 0
aaguid: 00000000-0000-0000-0000-000000000000
credentialIdLength: 16
credentialId: [base64url-encoded-id]
credentialPublicKey: [cbor-encoded-key-preview]
------------------------
attStmt: {}
```

This detailed decoding helps with:
- Debugging WebAuthn flows
- Understanding the internal structure of credentials
- Verifying correct flag settings and credential data

## WebAuthn.io Example Scripts

The project includes two example scripts that demonstrate how to use FIDO2 Client Simulator with the WebAuthn.io demo site. These scripts provide a complete end-to-end demonstration of both registration and authentication flows.

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

### Registration Script (webauthn-io-tutorial-registration.sh)

This script demonstrates a complete FIDO2 registration flow with webauthn.io:

1. **Fetch Registration Options**: Uses curl to request registration options from webauthn.io
2. **Create Credential**: Passes the options to fido2-client-simulator to create a new credential
3. **Verify Registration**: Submits the credential back to webauthn.io for verification

To run the script:
```bash
./webauthn-io-tutorial-registration.sh
```

The script outputs detailed information about each step of the process and saves all request/response data in the `target/webauthn-io-tutorial` directory for later analysis.

### Authentication Script (webauthn-io-tutorial-authentication.sh)

This script demonstrates a complete FIDO2 authentication flow with webauthn.io:

1. **Fetch Authentication Options**: Uses curl to request authentication options from webauthn.io
2. **Generate Assertion**: Passes the options to fido2-client-simulator to generate an assertion
3. **Verify Authentication**: Submits the assertion back to webauthn.io for verification

To run the script:
```bash
./webauthn-io-tutorial-authentication.sh
```

**Note**: You should run the registration script first to create a credential before running the authentication script.

### Flow Breakdown

#### Registration Flow:
1. Script sends a request to webauthn.io for registration options
2. webauthn.io responds with PublicKeyCredentialCreationOptions
3. fido2-client-simulator receives the options and creates a credential
4. Script sends the credential back to webauthn.io for verification
5. webauthn.io verifies the credential and confirms success

#### Authentication Flow:
1. Script sends a request to webauthn.io for authentication options
2. webauthn.io responds with PublicKeyCredentialRequestOptions
3. fido2-client-simulator receives the options and generates an assertion
4. Script sends the assertion back to webauthn.io for verification
5. webauthn.io verifies the assertion and confirms success

### Benefits of Using These Scripts

- Demonstrates real-world FIDO2 flows with a public WebAuthn demo site
- Shows how to integrate the simulator with web applications
- Provides examples of handling JSON data between different components
- Useful for learning WebAuthn/FIDO2 protocols and debugging issues
- All intermediate files are saved for inspection and analysis

## Notes
- Change the keystore password in production!
- The default AAGUID is all zeros (software authenticator)
- For best results with scripting, use the `--json-only` option
- When debugging, combine `--pretty` and `--verbose` options
- See the code for more details and documentation

---

## System Architecture

The FIDO2 Client Simulator is designed following SOLID principles and modern design patterns to ensure maintainability, testability, and extensibility.

### Component Diagram

```mermaid
graph TD
    CLI[CLI - Command Line Interface] --> App[Fido2ClientApp]
    App --> Factory[HandlerFactory]
    Factory --> CreateH[CreateHandler]
    Factory --> GetH[GetHandler]
    CreateH --> CredStore[CredentialStore]
    GetH --> CredStore
    CredStore --> KeyStore[KeyStoreManager]
    KeyStore --> PKCS12[(PKCS12 KeyStore)]
    KeyStore --> MetaData[(JSON Metadata)]
    
    classDef interface fill:#f9f,stroke:#333,stroke-dasharray: 5 5;
    classDef implementation fill:#9cf,stroke:#333;
    classDef data fill:#fcf,stroke:#333;
    
    class CredStore interface;
    class KeyStore,CreateH,GetH,Factory implementation;
    class PKCS12,MetaData data;
```

### Implemented Design Patterns

#### 1. Repository Pattern (CredentialStore)

`CredentialStore` acts as an abstract repository for credential storage operations, decoupling business logic from the persistence mechanism:

```java
public interface CredentialStore {
    Optional<PublicKey> getPublicKey(ByteArray credentialId) throws KeyStoreException;
    Optional<PrivateKey> getPrivateKey(ByteArray credentialId) throws KeyStoreException, UnrecoverableKeyException;
    boolean hasCredential(ByteArray credentialId);
    List<ByteArray> getCredentialIdsForRpId(String rpId);
    // ... other methods
}
```

#### 2. Factory Pattern (HandlerFactory)

Implementation of the Factory pattern for creating specific handlers:

```java
public class HandlerFactory {
    // ...
    public CredentialHandler createHandler(String operation, boolean interactive) {
        if ("create".equalsIgnoreCase(operation)) {
            return new CreateHandler(credentialStore, jsonMapper);
        } else if ("get".equalsIgnoreCase(operation)) {
            return new GetHandler(credentialStore, jsonMapper, interactive);
        }
        throw new IllegalArgumentException("Unknown operation: " + operation);
    }
}
```

#### 3. Strategy Pattern (Handlers)

The `CreateHandler` and `GetHandler` handlers implement different strategies for processing FIDO2 operations, sharing the common `CredentialHandler` interface.

#### 4. Functional Programming and Optional

Use of modern functional programming techniques for more concise and safer code:

```java
default List<ByteArray> getCredentialsByPredicate(Predicate<CredentialMetadata> filter) {
    Objects.requireNonNull(filter, "The filter predicate cannot be null");
    
    return getMetadataMap().values().stream()
            .filter(filter)
            .map(this::extractCredentialId)
            .filter(Optional::isPresent)
            .map(Optional::get)
            .collect(Collectors.toUnmodifiableList());
}
```

### Architecture Benefits

1. **Testability**: The use of interfaces facilitates testing with mocks.
2. **Extensibility**: New storage types can implement `CredentialStore`.
3. **Maintainability**: Clear separation of responsibilities.
4. **Security**: Robust exception handling and input validation.
5. **Evolution**: Facilitates the incorporation of new features without modifying existing code.

© 2025 Jordi Murgo (jordi.murgo@gmail.com). FIDO2 Client Simulator. MIT License.
