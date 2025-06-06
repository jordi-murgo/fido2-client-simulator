#!/bin/bash

# Colors for better output readability
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
HTTP_SERVER_URL="http://localhost:8080"
TEST_DIR="target/webauthn-io-postman-test"
WEBAUTHN_IO_URL="https://webauthn.io"

# Create test directory
mkdir -p "$TEST_DIR"

echo -e "${BLUE}=== WebAuthn.io Integration Test (Postman Flow) ===${NC}"
echo -e "This script simulates the Postman collection WebAuthn.io integration flow"
echo ""

# Check if HTTP server is running
echo -e "${BLUE}Checking HTTP server status...${NC}"
SERVER_INFO=$(curl -s -f "$HTTP_SERVER_URL/info" 2>/dev/null)
if [ $? -ne 0 ]; then
    echo -e "${RED}✗ HTTP server is not running on $HTTP_SERVER_URL${NC}"
    echo -e "${YELLOW}Please start the server with: java -jar target/fido2-client-simulator-1.3.0-SNAPSHOT.jar --listen 8080${NC}"
    exit 1
fi

# Parse and display server info
SERVER_NAME=$(echo "$SERVER_INFO" | jq -r '.name // "Unknown"')
SERVER_VERSION=$(echo "$SERVER_INFO" | jq -r '.version // "Unknown"')
SERVER_STATUS=$(echo "$SERVER_INFO" | jq -r '.status // "Unknown"')
SERVER_UPTIME=$(echo "$SERVER_INFO" | jq -r '.uptime // "Unknown"')

echo -e "${GREEN}✓ HTTP server is running${NC}"
echo -e "  Server: $SERVER_NAME v$SERVER_VERSION"
echo -e "  Status: $SERVER_STATUS (uptime: $SERVER_UPTIME)"

# Step 1: Get WebAuthn.io Registration Options
echo -e "\n${BLUE}Step 1: Get WebAuthn.io Registration Options${NC}"
REG_OPTIONS_PAYLOAD='{
    "username": "postman_user",
    "user_verification": "preferred",
    "attestation": "direct",
    "attachment": "platform",
    "rp": {
        "name": "WebAuthn.io",
        "id": "webauthn.io"
    },
    "discoverable_credential": "preferred",
    "algorithms": ["es256", "rs256"]
}'

REG_OPTIONS_RESPONSE=$(curl -s -X POST "$WEBAUTHN_IO_URL/registration/options" \
    -H "Content-Type: application/json" \
    -H "Origin: https://webauthn.io" \
    -d "$REG_OPTIONS_PAYLOAD")

echo "$REG_OPTIONS_RESPONSE" > "$TEST_DIR/reg_options_response.json"

if ! jq -e . "$TEST_DIR/reg_options_response.json" > /dev/null 2>&1; then
    echo -e "${RED}✗ Failed to get registration options - invalid JSON response${NC}"
    echo -e "${RED}Response: $(cat "$TEST_DIR/reg_options_response.json")${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Got registration options from webauthn.io${NC}"
CHALLENGE=$(jq -r '.challenge' "$TEST_DIR/reg_options_response.json")
echo -e "Challenge: ${CHALLENGE:0:20}..."

# Step 2: Create Credential via HTTP Server
echo -e "\n${BLUE}Step 2: Create Credential via HTTP Server${NC}"
CREDENTIAL_RESPONSE=$(curl -s -X POST "$HTTP_SERVER_URL/create" \
    -H "Content-Type: application/json" \
    -d @"$TEST_DIR/reg_options_response.json")

echo "$CREDENTIAL_RESPONSE" > "$TEST_DIR/credential_response.json"

if ! jq -e . "$TEST_DIR/credential_response.json" > /dev/null 2>&1; then
    echo -e "${RED}✗ Failed to create credential via HTTP server${NC}"
    echo -e "${RED}Response: $(cat "$TEST_DIR/credential_response.json")${NC}"
    exit 1
fi

CREDENTIAL_ID=$(jq -r '.id // empty' "$TEST_DIR/credential_response.json")
if [ -z "$CREDENTIAL_ID" ]; then
    echo -e "${RED}✗ Failed to get credential ID${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Created credential via HTTP server${NC}"
echo -e "Credential ID: ${CREDENTIAL_ID:0:20}..."

# Step 3: Verify Registration with WebAuthn.io
echo -e "\n${BLUE}Step 3: Verify Registration with WebAuthn.io${NC}"
REG_VERIFY_PAYLOAD=$(jq -n --argjson response "$(cat "$TEST_DIR/credential_response.json")" \
    '{
        "username": "postman_user",
        "response": $response
    }')

REG_VERIFY_RESPONSE=$(curl -s -X POST "$WEBAUTHN_IO_URL/registration/verification" \
    -H "Content-Type: application/json" \
    -H "Origin: https://webauthn.io" \
    -d "$REG_VERIFY_PAYLOAD")

echo "$REG_VERIFY_RESPONSE" > "$TEST_DIR/reg_verify_response.json"

if ! jq -e . "$TEST_DIR/reg_verify_response.json" > /dev/null 2>&1; then
    echo -e "${RED}✗ Invalid JSON response from webauthn.io${NC}"
    echo -e "${RED}Response: $(cat "$TEST_DIR/reg_verify_response.json")${NC}"
    exit 1
fi

# Check verification result (webauthn.io may return different success indicators)
if jq -e '.success // (has("error") | not)' "$TEST_DIR/reg_verify_response.json" > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Registration verified successfully on webauthn.io${NC}"
else
    ERROR_MSG=$(jq -r '.error // .message // "Unknown error"' "$TEST_DIR/reg_verify_response.json" 2>/dev/null || echo "Unknown error")
    echo -e "${RED}✗ Registration verification failed: $ERROR_MSG${NC}"
    exit 1
fi

# Step 4: Get WebAuthn.io Authentication Options
echo -e "\n${BLUE}Step 4: Get WebAuthn.io Authentication Options${NC}"
AUTH_OPTIONS_PAYLOAD='{
    "username": "postman_user",
    "user_verification": "preferred",
    "attachment": "platform"
}'

AUTH_OPTIONS_RESPONSE=$(curl -s -X POST "$WEBAUTHN_IO_URL/authentication/options" \
    -H "Content-Type: application/json" \
    -H "Origin: https://webauthn.io" \
    -d "$AUTH_OPTIONS_PAYLOAD")

echo "$AUTH_OPTIONS_RESPONSE" > "$TEST_DIR/auth_options_response.json"

if ! jq -e . "$TEST_DIR/auth_options_response.json" > /dev/null 2>&1; then
    echo -e "${RED}✗ Failed to get authentication options${NC}"
    echo -e "${RED}Response: $(cat "$TEST_DIR/auth_options_response.json")${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Got authentication options from webauthn.io${NC}"
AUTH_CHALLENGE=$(jq -r '.challenge' "$TEST_DIR/auth_options_response.json")
echo -e "Challenge: ${AUTH_CHALLENGE:0:20}..."

# Step 5: Generate Assertion via HTTP Server
echo -e "\n${BLUE}Step 5: Generate Assertion via HTTP Server${NC}"
ASSERTION_RESPONSE=$(curl -s -X POST "$HTTP_SERVER_URL/get" \
    -H "Content-Type: application/json" \
    -d @"$TEST_DIR/auth_options_response.json")

echo "$ASSERTION_RESPONSE" > "$TEST_DIR/assertion_response.json"

if ! jq -e . "$TEST_DIR/assertion_response.json" > /dev/null 2>&1; then
    echo -e "${RED}✗ Failed to generate assertion via HTTP server${NC}"
    echo -e "${RED}Response: $(cat "$TEST_DIR/assertion_response.json")${NC}"
    exit 1
fi

ASSERTION_ID=$(jq -r '.id // empty' "$TEST_DIR/assertion_response.json")
if [ -z "$ASSERTION_ID" ]; then
    echo -e "${RED}✗ Failed to get assertion ID${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Generated assertion via HTTP server${NC}"
echo -e "Assertion ID: ${ASSERTION_ID:0:20}..."

# Step 6: Verify Authentication with WebAuthn.io
echo -e "\n${BLUE}Step 6: Verify Authentication with WebAuthn.io${NC}"
AUTH_VERIFY_PAYLOAD=$(jq -n --argjson response "$(cat "$TEST_DIR/assertion_response.json")" \
    '{
        "username": "postman_user",
        "response": $response
    }')

AUTH_VERIFY_RESPONSE=$(curl -s -X POST "$WEBAUTHN_IO_URL/authentication/verification" \
    -H "Content-Type: application/json" \
    -H "Origin: https://webauthn.io" \
    -d "$AUTH_VERIFY_PAYLOAD")

echo "$AUTH_VERIFY_RESPONSE" > "$TEST_DIR/auth_verify_response.json"

if ! jq -e . "$TEST_DIR/auth_verify_response.json" > /dev/null 2>&1; then
    echo -e "${RED}✗ Invalid JSON response from webauthn.io${NC}"
    echo -e "${RED}Response: $(cat "$TEST_DIR/auth_verify_response.json")${NC}"
    exit 1
fi

# Check authentication verification result
if jq -e '.verified == true' "$TEST_DIR/auth_verify_response.json" > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Authentication verified successfully on webauthn.io!${NC}"
else
    ERROR_MSG=$(jq -r '.message // "Authentication verification failed"' "$TEST_DIR/auth_verify_response.json" 2>/dev/null || echo "Unknown error")
    echo -e "${RED}✗ Authentication verification failed: $ERROR_MSG${NC}"
    exit 1
fi

# Summary
echo -e "\n${GREEN}=== WebAuthn.io Integration Test Complete! ===${NC}"
echo -e "${GREEN}✓ Registration flow: webauthn.io → HTTP server → webauthn.io${NC}"
echo -e "${GREEN}✓ Authentication flow: webauthn.io → HTTP server → webauthn.io${NC}"
echo -e "\nAll test files saved in: $TEST_DIR"
echo -e "\n${BLUE}This demonstrates the same flow that the Postman collection performs automatically!${NC}" 
