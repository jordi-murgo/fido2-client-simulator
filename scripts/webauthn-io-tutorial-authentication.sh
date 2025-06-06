#!/bin/bash

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source common functions
source "$SCRIPT_DIR/common-functions.sh"

# Setup environment (check dependencies and locate JAR)
setup_environment

# Create test directory
TEST_DIR="target/webauthn-io-tutorial"
mkdir -p "$TEST_DIR"

echo -e "${BLUE}=== WebAuthn.io Authentication Tutorial ===${NC}"


# Get cookies first
echo -e "\n${BLUE}Getting cookies...${NC}"
curl -s -k -c "$TEST_DIR/cookies.txt" "https://webauthn.io/" > /dev/null

# Step 1: Get authentication options
echo -e "\n${BLUE}Step 1: Get authentication options${NC}"
AUTH_OPTIONS_PAYLOAD='{
    "username": "tutorial_user",
    "user_verification": "preferred",
    "attachment": "platform"
}'

echo "$AUTH_OPTIONS_PAYLOAD" > "$TEST_DIR/auth_options_request.json"

# Get authentication options
AUTH_OPTIONS_RESPONSE=$(curl -s -k -X POST "https://webauthn.io/authentication/options" \
    -H "content-type: application/json" \
    -H "origin: https://webauthn.io" \
    -b "$TEST_DIR/cookies.txt" \
    -d "@$TEST_DIR/auth_options_request.json")

echo "$AUTH_OPTIONS_RESPONSE" > "$TEST_DIR/auth_options_response.json"

# Check if we got a valid response
if ! jq -e . "$TEST_DIR/auth_options_response.json" > /dev/null 2>&1; then
    echo -e "${RED}✗ Failed to get authentication options - invalid JSON response${NC}"
    echo -e "${RED}Response: $(cat "$TEST_DIR/auth_options_response.json")${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Got authentication options${NC}"

# Step 2: Generate assertion
echo -e "\n${BLUE}Step 2: Generate assertion${NC}"
java -jar "$JAR_PATH" get --json-only --output "$TEST_DIR/assertion_response.json" --verbose < "$TEST_DIR/auth_options_response.json"

# Check if assertion was generated successfully
if [ ! -f "$TEST_DIR/assertion_response.json" ] || ! jq -e . "$TEST_DIR/assertion_response.json" > /dev/null 2>&1; then
    echo -e "${RED}✗ Failed to generate assertion${NC}"
    if [ -f "$TEST_DIR/assertion_response.json" ]; then
        echo -e "${RED}Error: $(cat "$TEST_DIR/assertion_response.json")${NC}"
    fi
    exit 1
fi

echo -e "${GREEN}✓ Generated assertion${NC}"

# Step 3: Verify authentication
echo -e "\n${BLUE}Step 3: Verify authentication${NC}"
ASSERTION_ID=$(jq -r '.id // empty' "$TEST_DIR/assertion_response.json")

if [ -z "$ASSERTION_ID" ]; then
    echo -e "${RED}✗ Failed to get assertion ID${NC}"
    exit 1
fi

# El API requiere un json con el siguiente formato:
AUTH_VERIFY_PAYLOAD=$(jq -n --argjson response "$(cat "$TEST_DIR/assertion_response.json")" \
    '{
        "username": "tutorial_user",
        "response": $response
    }')

echo "$AUTH_VERIFY_PAYLOAD" > "$TEST_DIR/auth_verify_request.json"

AUTH_VERIFY_RESPONSE=$(curl -s -k -X POST "https://webauthn.io/authentication/verification" \
    -H "content-type: application/json" \
    -H "origin: https://webauthn.io" \
    -b "$TEST_DIR/cookies.txt" \
    -d "@$TEST_DIR/auth_verify_request.json")

echo "$AUTH_VERIFY_RESPONSE" > "$TEST_DIR/auth_verify_response.json"

# Check verification result
if [ -f "$TEST_DIR/auth_verify_response.json" ] && \
   jq -e '.verified' "$TEST_DIR/auth_verify_response.json" > /dev/null 2>&1 && \
   [ "$(jq -r '.verified' "$TEST_DIR/auth_verify_response.json")" == "true" ]; then
    echo -e "${GREEN}✓ Authentication verified successfully!${NC}"
else
    ERROR_MSG=$(jq -r '.message // "Unknown error"' "$TEST_DIR/auth_verify_response.json" 2>/dev/null || echo "Response file not found")
    echo -e "${RED}✗ Authentication verification failed: $ERROR_MSG${NC}"
fi

echo -e "\n${BLUE}=== Tutorial Complete ===${NC}"
echo -e "All files saved in: $TEST_DIR" 
