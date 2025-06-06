#!/bin/bash

# Colors for better output readability
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Verificar dependencias necesarias
echo -e "${BLUE}=== Verificando dependencias necesarias ===${NC}"

# Función para verificar si un comando existe
check_command() {
    local cmd=$1
    local name=$2
    
    if command -v "$cmd" &> /dev/null; then
        echo -e "${GREEN}✓ $name encontrado${NC}"
        return 0
    else
        echo -e "${RED}✗ $name no encontrado${NC}"
        return 1
    fi
}

# Verificar Java
JAVA_OK=0
if ! check_command java "Java"; then
    JAVA_OK=1
    echo -e "${YELLOW}Instrucciones para instalar Java:${NC}"
    echo "  Windows: Descarga JDK desde https://adoptium.net/"
    echo "  macOS: brew install --cask temurin"
    echo "  Linux: sudo apt install default-jdk"
    echo ""
fi

# Verificar curl
CURL_OK=0
if ! check_command curl "curl"; then
    CURL_OK=1
    echo -e "${YELLOW}Instrucciones para instalar curl:${NC}"
    echo "  Windows: winget install cURL"
    echo "  macOS: brew install curl"
    echo "  Linux: sudo apt install curl"
    echo ""
fi

# Verificar jq
JQ_OK=0
if ! check_command jq "jq"; then
    JQ_OK=1
    echo -e "${YELLOW}Instrucciones para instalar jq:${NC}"
    echo "  Windows: winget install jqlang.jq"
    echo "  macOS: brew install jq"
    echo "  Linux: sudo apt install jq"
    echo ""
fi

# Salir si falta alguna dependencia
if [ $JAVA_OK -eq 1 ] || [ $CURL_OK -eq 1 ] || [ $JQ_OK -eq 1 ]; then
    echo -e "${RED}Error: Faltan dependencias necesarias. Por favor, instale las herramientas faltantes e intente de nuevo.${NC}"
    exit 1
fi

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
