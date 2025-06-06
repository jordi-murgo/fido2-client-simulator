# FIDO2 WebAuthn.io Tutorial Scripts

This directory contains scripts for testing and demonstrating the FIDO2 Client Simulator with WebAuthn.io.

## Files

### Tutorial Scripts

- `webauthn-io-tutorial-registration.sh` - Demonstrates credential registration flow
- `webauthn-io-tutorial-authentication.sh` - Demonstrates authentication flow using existing credentials

### Shared Components

- `common-functions.sh` - Shared functions for dependency checking and JAR detection

### Other Scripts

- `test-webauthn-io-postman-flow.sh` - Comprehensive test script that simulates Postman collection behavior
- `verify-signature.sh` - Utility script for signature verification

## Usage

### Registration Tutorial

```bash
bash scripts/webauthn-io-tutorial-registration.sh
```

### Authentication Tutorial

```bash
bash scripts/webauthn-io-tutorial-authentication.sh
```

**Note**: Authentication requires a previously registered credential.

## Common Functions

The `common-functions.sh` file provides shared functionality:

### Functions

- `check_command()` - Verifies if a command exists
- `check_dependencies()` - Checks all required dependencies (Java, curl, jq)
- `find_latest_jar()` - Finds the most recent JAR file by modification date
- `setup_jar_path()` - Locates and validates the JAR file
- `setup_environment()` - Main setup function that checks everything

### Dependencies

All scripts require:

- **Java** - To run the FIDO2 client simulator
- **curl** - To make HTTP requests to WebAuthn.io
- **jq** - To parse and manipulate JSON responses

### Automatic JAR Detection

The scripts automatically find the most recent `fido2-client-simulator-*.jar` file in the `target/` directory, sorted by modification date. This means you don't need to update script references when building new versions.

## Error Handling

The scripts include comprehensive error handling:

- Dependency verification with installation instructions
- JAR file detection and validation
- HTTP response validation
- JSON parsing error handling
- Network connectivity checks

## Compatibility

- Scripts use bash for maximum compatibility
- Work from any directory (automatic path resolution)
- Handle multiple JAR versions gracefully
- Provide clear error messages and instructions
