# FIDO2 Client Simulator

A Java command-line application that simulates a FIDO2 authenticator for registration (`create`) and authentication (`get`) flows, with enhanced debugging and interoperability features.

## Features
- Simulates `navigator.credentials.create()` and `navigator.credentials.get()`
- Input: JSON for `PublicKeyCredentialCreationOptions` (create) or `PublicKeyCredentialRequestOptions` (get)
- Output: JSON representing the FIDO2 `PublicKeyCredential` response
- Enhanced metadata storage in JSON format with rich credential information
- PEM-encoded public key storage for improved interoperability
- Detailed attestation and authenticator data decoding for debugging
- Key storage: Java KeyStore (PKCS12) for secure credential operations
- Crypto: Uses BouncyCastle and Yubico's WebAuthn libraries
- JSON: Uses Jackson with CBOR support
- CLI: Uses Picocli

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
java -jar target/fido2-client-simulator-1.0-SNAPSHOT.jar get
# (paste JSON, then Ctrl+D)
```

---

### Credential Selection Behavior (`get`)

If the input JSON for authentication does **not** include `allowCredentials`, the simulator will:

- **Search for all credentials stored for the given `rpId`.**
- If only one exists, it is used automatically.
- If multiple exist:
  - By default (non-interactive), the first credential is used and a warning is printed.
  - If you add `--interactive`, the CLI will prompt you to select which credential to use.

**Example with interactive selection:**
```bash
java -jar target/fido2-client-simulator-1.0-SNAPSHOT.jar get --file get_options.json --interactive
```

This matches the behavior of modern authenticators and allows for both scripting and manual workflows.

## Files
- `fido2_keystore.p12`: Stores credential private keys in PKCS12 format
- `fido2_metadata.json`: Stores rich credential metadata including:
  - Registration response JSON
  - RP information
  - User information
  - PEM-encoded public key
  - Creation timestamp

## Advanced Features

### PEM-Encoded Public Key Storage
Each credential's public key is stored in standard PEM format (X.509 SubjectPublicKeyInfo) in the metadata, enabling:
- Easy interoperability with other systems and languages
- Direct use for signature verification without accessing the keystore
- Standard format for cryptographic operations

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

## Notes
- Change the keystore password in production!
- The default AAGUID is all zeros (software authenticator)
- See the code for more details and documentation

---

© 2025 FIDO2 Client Simulator. MIT License.
