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
    
    if command -v $cmd &> /dev/null; then
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

echo -e "${BLUE}=== WebAuthn.io Registration Tutorial ===${NC}"

# Get cookies first
echo -e "\n${BLUE}Getting cookies...${NC}"
curl -s -k -c "$TEST_DIR/cookies.txt" "https://webauthn.io/" > /dev/null

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
REG_OPTIONS_RESPONSE=$(curl -s -k -X POST "https://webauthn.io/registration/options" \
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

# Send verification request
REG_VERIFY_RESPONSE=$(curl -s -k -X POST "https://webauthn.io/registration/verification" \
    -H "content-type: application/json" \
    -H "origin: https://webauthn.io" \
    -b "$TEST_DIR/cookies.txt" \
    -d "@$TEST_DIR/reg_verify_request.json")

echo "$REG_VERIFY_RESPONSE" > "$TEST_DIR/reg_verify_response.json"

# Check verification result
if [ -f "$TEST_DIR/reg_verify_response.json" ]; then
    # Check if the response is valid JSON
    if ! jq -e . "$TEST_DIR/reg_verify_response.json" > /dev/null 2>&1; then
        echo -e "${RED}✗ Invalid JSON response from server${NC}"
        echo -e "${RED}Response: $(cat "$TEST_DIR/reg_verify_response.json")${NC}"
        exit 1
    fi

    # Check if the response indicates success by looking for a success field or absence of error
    if jq -e '.success // (has("error") | not)' "$TEST_DIR/reg_verify_response.json" > /dev/null 2>&1; then
        echo -e "${GREEN}✓ Registration verified successfully${NC}"
        echo -e "\n${GREEN}=== Registration Details ===${NC}"
        echo -e "Credential ID: ${BLUE}$CREDENTIAL_ID${NC}"
        echo -e "Verification Response: ${BLUE}$TEST_DIR/reg_verify_response.json${NC}"
    else
        # Extract error message from response if available
        ERROR_MSG=$(jq -r '.error // .message // "Unknown error"' "$TEST_DIR/reg_verify_response.json" 2>/dev/null || echo "Unknown error")
        
        echo -e "${RED}✗ Registration verification failed: $ERROR_MSG${NC}"
        echo -e "\n${RED}=== Error Details ===${NC}"
        echo -e "${RED}Response:${NC}"
        jq . "$TEST_DIR/reg_verify_response.json"
        
        exit 1
    fi
fi

echo -e "\n${BLUE}=== Tutorial Complete ===${NC}"
echo -e "All files saved in: $TEST_DIR"
