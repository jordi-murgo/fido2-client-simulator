# FIDO2 Client Simulator - HTTP Server Mode

## Description

The FIDO2 Client Simulator now includes an HTTP server mode that allows exposing FIDO2 operations as REST endpoints. This facilitates integration with web applications and services that need to simulate FIDO2 operations.

## Usage

### Starting the HTTP server

```bash
java -jar fido2-client-simulator-1.3.0-SNAPSHOT.jar --listen <PORT>
```

Example:

```bash
java -jar fido2-client-simulator-1.3.0-SNAPSHOT.jar --listen 8080
```

### Additional options

- `--verbose`: Enables detailed logging
- `--pretty`: Formats JSON responses with indentation
- `--format <format>`: Specifies output format for binary fields

Example with options:

```bash
java -jar fido2-client-simulator-1.3.0-SNAPSHOT.jar --listen 8080 --verbose --pretty
```

## Available endpoints

### POST /create

Creates a new FIDO2 credential.

**Request:**

- Method: `POST`
- Content-Type: `application/json`
- Body: JSON with credential creation options
- Query Parameters (optional):
  - `format`: Output format for binary fields (`default`, `bytes`, `ints`, `ping`)
  - `pretty`: Pretty-print JSON response (`true`, `false`, `1`, `0`, `yes`, `no`)
  - `verbose`: Enable verbose logging (`true`, `false`, `1`, `0`, `yes`, `no`)
  - `remove-nulls`: Remove null values from response (`true`, `false`, `1`, `0`, `yes`, `no`)

**Request examples:**

Basic request:
```bash
curl -X POST http://localhost:8080/create \
  -H "Content-Type: application/json" \
  -d '{
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
      { "type": "public-key", "alg": -257 },
      { "type": "public-key", "alg": -7 }
    ],
    "authenticatorSelection": {
      "userVerification": "required",
      "requireResidentKey": false,
      "authenticatorAttachment": "platform"
    },
    "attestation": "direct"
  }'
```

With format and pretty-print parameters:

```bash
curl -X POST "http://localhost:8080/create?format=bytes&pretty=true" \
  -H "Content-Type: application/json" \
  -d '{
    "rp": {"name": "Test RP", "id": "localhost"},
    "user": {"name": "testuser", "displayName": "Test User", "id": "dGVzdA"},
    "challenge": "AAAAAAAAAAAAAAAAAAAAAA",
    "pubKeyCredParams": [{"type": "public-key", "alg": -7}]
  }'
```

**Successful response:**

```json
{
  "id": "ya48ISqOQnarCZCez6jBxQ",
  "rawId": "ya48ISqOQnarCZCez6jBxQ",
  "type": "public-key",
  "authenticatorAttachment": "platform",
  "response": {
    "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIi...",
    "attestationObject": "v2NmbXRkbm9uZWhhdXRoRGF0YVk...",
    "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4...",
    "transports": ["internal"],
    "publicKey": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...",
    "publicKeyAlgorithm": -257
  }
}
```

### POST /get

Authenticates using an existing FIDO2 credential.

**Request:**

- Method: `POST`
- Content-Type: `application/json`
- Body: JSON with authentication options
- Query Parameters (optional):
  - `format`: Output format for binary fields (`default`, `bytes`, `ints`, `ping`)
  - `pretty`: Pretty-print JSON response (`true`, `false`, `1`, `0`, `yes`, `no`)
  - `verbose`: Enable verbose logging (`true`, `false`, `1`, `0`, `yes`, `no`)
  - `remove-nulls`: Remove null values from response (`true`, `false`, `1`, `0`, `yes`, `no`)

**Request examples:**

Basic request:
```bash
curl -X POST http://localhost:8080/get \
  -H "Content-Type: application/json" \
  -d '{
    "challenge": "BBBBBBBBBBBBBBBBBBBBBB",
    "rpId": "localhost",
    "allowCredentials": [
      {
        "type": "public-key",
        "id": "6T9pAhKGT7qZHQauKklhig"
      }
    ],
    "userVerification": "discouraged",
    "extensions": {}
  }'
```

With format parameters:

```bash
curl -X POST "http://localhost:8080/get?format=ping&pretty=true" \
  -H "Content-Type: application/json" \
  -d '{
    "challenge": "BBBBBBBBBBBBBBBBBBBBBB",
    "rpId": "localhost",
    "userVerification": "discouraged"
  }'
```

### GET /info

Gets detailed information about the server, stored credentials, and system status.

**Request:**

- Method: `GET`
- Query Parameters (optional):
  - `format`: Output format for binary fields (`default`, `bytes`, `ints`, `ping`)
  - `pretty`: Pretty-print JSON response (`true`, `false`, `1`, `0`, `yes`, `no`)
  - `verbose`: Enable verbose logging (`true`, `false`, `1`, `0`, `yes`, `no`)
  - `remove-nulls`: Remove null values from response (`true`, `false`, `1`, `0`, `yes`, `no`)

**Request examples:**

Basic request:

```bash
curl http://localhost:8080/info
```

With pretty-print:

```bash
curl "http://localhost:8080/info?pretty=true"
```

**Response example:**

```json
{
  "totalCredentials": 5,
  "relyingParties": ["localhost", "webauthn.io"],
  "credentials": [
    {
      "id": "HMznIHK3SKK32lewKBWYpQ",
      "createdAt": "2025-06-06 08:58:44",
      "signCount": 0,
      "relyingParty": {
        "name": "webauthn.io",
        "id": "webauthn.io"
      },
      "user": {
        "name": "tutorial_user",
        "displayName": "Tutorial User"
      }
    }
  ]
}
```

## Error handling

All errors are returned as JSON with the following format:

```json
{
  "error": "Error description"
}
```

### HTTP status codes

- `200`: Successful operation
- `400`: Invalid request (empty body, malformed JSON, etc.)
- `404`: Not found (invalid URL)
- `405`: Method not allowed (only POST is accepted)
- `500`: Internal server error

## Query Parameters

All endpoints (`/create`, `/get`, and `/info`) support the following optional query parameters:

### Format Parameter

The `format` parameter controls how binary fields are encoded in the response:

- `default`: Uses base64url encoding for all binary fields (WebAuthn standard)
- `bytes`: Outputs binary data as arrays of signed bytes (-128 to 127)
- `ints`: Outputs binary data as arrays of unsigned integers (0-255)
- `ping`: Optimized format for Ping Identity compatibility

Example:

```bash
curl -X POST "http://localhost:8080/create?format=bytes" \
  -H "Content-Type: application/json" \
  -d '{"rp": {"name": "Test", "id": "localhost"}, ...}'
```

### Pretty Parameter

The `pretty` parameter enables JSON pretty-printing for better readability:

Accepted values: `true`, `false`, `1`, `0`, `yes`, `no`

Example:

```bash
curl "http://localhost:8080/info?pretty=true"
```

### Verbose Parameter

The `verbose` parameter enables detailed logging for debugging:

Accepted values: `true`, `false`, `1`, `0`, `yes`, `no`

Example:

```bash
curl -X POST "http://localhost:8080/create?verbose=true&pretty=true" \
  -H "Content-Type: application/json" \
  -d '{"rp": {"name": "Test", "id": "localhost"}, ...}'
```

### Remove Nulls Parameter

The `remove-nulls` parameter removes null values from the JSON response:

Accepted values: `true`, `false`, `1`, `0`, `yes`, `no`

Example:

```bash
curl "http://localhost:8080/info?remove-nulls=true&pretty=true"
```

### Combining Parameters

Multiple query parameters can be combined:

```bash
curl -X POST "http://localhost:8080/create?format=ping&pretty=true&verbose=true" \
  -H "Content-Type: application/json" \
  -d '{"rp": {"name": "Test", "id": "localhost"}, ...}'
```

## Additional features

### CORS

The server includes CORS support with the following headers:

- `Access-Control-Allow-Origin: *`
- `Access-Control-Allow-Methods: POST, OPTIONS`
- `Access-Control-Allow-Headers: Content-Type`

### Preflight requests

The server properly handles OPTIONS requests for CORS preflight.

### Logging

With the `--verbose` option, the server logs:

- Received requests
- Sent responses
- Detailed errors

## Usage examples

### Using sample files

The project includes sample files in the `samples/` directory:

```bash
# Create credential using sample file
curl -X POST http://localhost:8080/create \
  -H "Content-Type: application/json" \
  -d @samples/create_options.json

# Authenticate using sample file
curl -X POST http://localhost:8080/get \
  -H "Content-Type: application/json" \
  -d @samples/get_options.json
```

### JavaScript integration

```javascript
// Create credential
const createResponse = await fetch('http://localhost:8080/create', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    rp: { name: "My App", id: "localhost" },
    user: { 
      name: "user@example.com",
      displayName: "User Example",
      id: btoa("user123")
    },
    challenge: btoa("random-challenge"),
    pubKeyCredParams: [
      { type: "public-key", alg: -257 }
    ]
  })
});

const credential = await createResponse.json();
console.log('Created credential:', credential);
```

## Stopping the server

To stop the server, press `Ctrl+C` in the terminal where it's running.
