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

echo -e "${BLUE}=== WebAuthn.io Authentication Tutorial ===${NC}"


# Get cookies first
echo -e "\n${BLUE}Getting cookies...${NC}"
curl -s -c "$TEST_DIR/cookies.txt" "https://webauthn.io/" > /dev/null

# Step 1: Get authentication options
echo -e "\n${BLUE}Step 1: Get authentication options${NC}"
AUTH_OPTIONS_PAYLOAD='{
    "username": "tutorial_user",
    "user_verification": "preferred",
    "attachment": "platform"
}'

echo "$AUTH_OPTIONS_PAYLOAD" > "$TEST_DIR/auth_options_request.json"

# Get authentication options
AUTH_OPTIONS_RESPONSE=$(curl -s -X POST "https://webauthn.io/authentication/options" \
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
java -jar "$JAR_PATH" get --json-only --output "$TEST_DIR/assertion_response.json" < "$TEST_DIR/auth_options_response.json"

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

AUTH_VERIFY_RESPONSE=$(curl -s -X POST "https://webauthn.io/authentication/verification" \
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
