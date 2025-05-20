#!/bin/bash

# Colors for better output readability
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Set the path to the JAR file
JAR_PATH="target/fido2-client-simulator-1.3.0-SNAPSHOT.jar"

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
java -jar "$JAR_PATH" create --json-only --output "$TEST_DIR/create_response.json" --verbose < "$TEST_DIR/reg_options_response.json"

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

# Save the full curl command for debugging
CURL_CMD="curl -v -X POST \"https://webauthn.io/registration/verification\" \
    -H \"content-type: application/json\" \
    -H \"origin: https://webauthn.io\" \
    -b \"$TEST_DIR/cookies.txt\" \
    -d @\"$TEST_DIR/reg_verify_request.json\""

echo -e "\n${BLUE}Debug: Sending verification request${NC}"
echo "$CURL_CMD"

# Save the full curl output including headers to a file for debugging
REG_VERIFY_RESPONSE=$(curl -v -X POST "https://webauthn.io/registration/verification" \
    -H "content-type: application/json" \
    -H "origin: https://webauthn.io" \
    -b "$TEST_DIR/cookies.txt" \
    2> "$TEST_DIR/reg_verify_curl_debug.txt" \
    -d "@$TEST_DIR/reg_verify_request.json")

echo "$REG_VERIFY_RESPONSE" > "$TEST_DIR/reg_verify_response.json"

# Check verification result
if [ -f "$TEST_DIR/reg_verify_response.json" ]; then
    # Check if the request was successful (HTTP 2xx)
    HTTP_STATUS=$(grep '^< HTTP/' "$TEST_DIR/reg_verify_curl_debug.txt" | tail -n 1 | cut -d' ' -f3)

    if [ -z "$HTTP_STATUS" ]; then
        echo -e "${RED}✗ No HTTP status received in response${NC}"
        echo -e "${RED}Curl debug output:${NC}"
        cat "$TEST_DIR/reg_verify_curl_debug.txt"
        exit 1
    fi

    # Check if the response is valid JSON
    if ! jq -e . "$TEST_DIR/reg_verify_response.json" > /dev/null 2>&1; then
        echo -e "${RED}✗ Invalid JSON response from server${NC}"
        echo -e "${RED}HTTP Status: $HTTP_STATUS${NC}"
        echo -e "${RED}Response: $(cat "$TEST_DIR/reg_verify_response.json")${NC}"
        echo -e "\n${RED}Curl debug output:${NC}"
        cat "$TEST_DIR/reg_verify_curl_debug.txt"
        exit 1
    fi

    # Check if the response indicates success
    if [ "$HTTP_STATUS" -ge 200 ] && [ "$HTTP_STATUS" -lt 300 ]; then
        echo -e "${GREEN}✓ Registration verified successfully (HTTP $HTTP_STATUS)${NC}"
        echo -e "\n${GREEN}=== Registration Details ===${NC}"
        echo -e "Credential ID: ${BLUE}$CREDENTIAL_ID${NC}"
        echo -e "Verification Response: ${BLUE}$TEST_DIR/reg_verify_response.json${NC}"
    else
        # Extract error message from response if available
        ERROR_MSG=$(jq -r '.error // .message // "Unknown error"' "$TEST_DIR/reg_verify_response.json" 2>/dev/null || echo "Unknown error")
        
        echo -e "${RED}✗ Registration verification failed (HTTP $HTTP_STATUS): $ERROR_MSG${NC}"
        echo -e "\n${RED}=== Error Details ===${NC}"
        echo -e "${RED}Response:${NC}"
        jq . "$TEST_DIR/reg_verify_response.json"
        
        # Show request payload for debugging
        echo -e "\n${RED}=== Request Payload ===${NC}"
        jq . "$TEST_DIR/reg_verify_request.json"
        
        # Show headers for debugging
        echo -e "\n${RED}=== Request Headers ===${NC}"
        grep -A 100 '^> ' "$TEST_DIR/reg_verify_curl_debug.txt" | head -n 20
        
        exit 1
    fi
fi

echo -e "\n${BLUE}=== Tutorial Complete ===${NC}"
echo -e "All files saved in: $TEST_DIR"
