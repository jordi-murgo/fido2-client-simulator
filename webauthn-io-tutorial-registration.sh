#!/bin/bash

# Colors for better output readability
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Set the path to the JAR file
JAR_PATH="target/fido2-client-simulator-1.0-SNAPSHOT.jar"

# Check if JAR exists
if [ ! -f "$JAR_PATH" ]; then
    echo -e "${RED}Error: JAR file not found at $JAR_PATH${NC}"
    echo -e "Please build the project using: mvn clean package"
    exit 1
fi

# Create test directory
TEST_DIR="target/webauthn-io-tutorial"
mkdir -p "$TEST_DIR"

echo -e "${BLUE}=== WebAuthn.io Registration Tutorial ===${NC}"

# Get cookies first
echo -e "\n${BLUE}Getting cookies...${NC}"
curl -s -c "$TEST_DIR/cookies.txt" "https://webauthn.io/" > /dev/null

# Step 1: Get registration options
echo -e "\n${BLUE}Step 1: Get registration options${NC}"
REG_OPTIONS_PAYLOAD='{
    "username": "tutorial_user",
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

echo "$REG_OPTIONS_PAYLOAD" > "$TEST_DIR/reg_options_request.json"


# Get registration options
REG_OPTIONS_RESPONSE=$(curl -s -X POST "https://webauthn.io/registration/options" \
    -H "content-type: application/json" \
    -H "origin: https://webauthn.io" \
    -b "$TEST_DIR/cookies.txt" \
    -d "@$TEST_DIR/reg_options_request.json")

echo "$REG_OPTIONS_RESPONSE" > "$TEST_DIR/reg_options_response.json"

# Check if we got a valid response
if ! jq -e . "$TEST_DIR/reg_options_response.json" > /dev/null 2>&1; then
    echo -e "${RED}✗ Failed to get registration options - invalid JSON response${NC}"
    echo -e "${RED}Response: $(cat "$TEST_DIR/reg_options_response.json")${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Got registration options${NC}"

# Step 2: Create credential
echo -e "\n${BLUE}Step 2: Create credential${NC}"
java -jar "$JAR_PATH" create --json-only --output "$TEST_DIR/create_response.json" < "$TEST_DIR/reg_options_response.json"

# Check if credential was created successfully
if [ ! -f "$TEST_DIR/create_response.json" ] || ! jq -e . "$TEST_DIR/create_response.json" > /dev/null 2>&1; then
    echo -e "${RED}✗ Failed to create credential${NC}"
    if [ -f "$TEST_DIR/create_response.json" ]; then
        echo -e "${RED}Error: $(cat "$TEST_DIR/create_response.json")${NC}"
    fi
    exit 1
fi

echo -e "${GREEN}✓ Created credential${NC}"

# Step 3: Verify registration
echo -e "\n${BLUE}Step 3: Verify registration${NC}"
CREDENTIAL_ID=$(jq -r '.id // empty' "$TEST_DIR/create_response.json")

if [ -z "$CREDENTIAL_ID" ]; then
    echo -e "${RED}✗ Failed to get credential ID${NC}"
    exit 1
fi

# El API requiere un json con el siguiente formato:
REG_VERIFY_PAYLOAD=$(jq -n --argjson response "$(cat "$TEST_DIR/create_response.json")" \
    '{
        "username": "tutorial_user",
        "response": $response
    }')

echo "$REG_VERIFY_PAYLOAD" > "$TEST_DIR/reg_verify_request.json"

REG_VERIFY_RESPONSE=$(curl -s -X POST "https://webauthn.io/registration/verification" \
    -H "content-type: application/json" \
    -H "origin: https://webauthn.io" \
    -b "$TEST_DIR/cookies.txt" \
    -d "@$TEST_DIR/reg_verify_request.json")

echo "$REG_VERIFY_RESPONSE" > "$TEST_DIR/reg_verify_response.json"

# Check verification result
if [ -f "$TEST_DIR/reg_verify_response.json" ] && \
   jq -e '.verified' "$TEST_DIR/reg_verify_response.json" > /dev/null 2>&1 && \
   [ "$(jq -r '.verified' "$TEST_DIR/reg_verify_response.json")" == "true" ]; then
    echo -e "${GREEN}✓ Registration verified successfully!${NC}"
else
    ERROR_MSG=$(jq -r '.message // "Unknown error"' "$TEST_DIR/reg_verify_response.json" 2>/dev/null || echo "Response file not found")
    echo -e "${RED}✗ Registration verification failed: $ERROR_MSG${NC}"
fi

echo -e "\n${BLUE}=== Tutorial Complete ===${NC}"
echo -e "All files saved in: $TEST_DIR" 
