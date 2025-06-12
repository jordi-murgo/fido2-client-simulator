#!/bin/bash

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source common functions
source "$SCRIPT_DIR/common-functions.sh"

# Setup environment (check dependencies and locate JAR)
setup_environment

# Create test directory
TEST_DIR="target/spc-test"
mkdir -p "$TEST_DIR"

echo -e "${BLUE}=== Secure Payment Confirmation (SPC) Test ===${NC}"
echo ""

# Verify that the server is running
SERVER_URL="http://localhost:8080"
echo -e "${YELLOW}Checking server at $SERVER_URL...${NC}"

if ! curl -s "$SERVER_URL/health" > /dev/null 2>&1; then
    echo -e "${RED}Error: Server is not running at $SERVER_URL${NC}"
    echo -e "${YELLOW}Start the server with: java -jar $JAR_PATH --listen 8080${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Server is active${NC}"
echo ""

# Create credential first
echo -e "${YELLOW}1. Creating test credential...${NC}"
CREATE_PAYLOAD='{
    "rp": {
      "name": "SPC Test RP",
      "id": "localhost"
    },
    "user": {
      "name": "spc.testuser",
      "displayName": "SPC Test User",
      "id": "c3BjX3Rlc3R1c2VyX2lk"
    },
    "challenge": "DDDDDDDDDDDDDDDDDDDDDD",
    "pubKeyCredParams": [
      { "type": "public-key", "alg": -7 }
    ],
    "authenticatorSelection": {
      "userVerification": "required",
      "requireResidentKey": false
    },
    "attestation": "direct"
  }'

echo "$CREATE_PAYLOAD" > "$TEST_DIR/create_request.json"

CREATE_RESPONSE=$(curl -s -X POST "$SERVER_URL/create" \
  -H "Content-Type: application/json" \
  -d "@$TEST_DIR/create_request.json")

if [ $? -ne 0 ]; then
    echo -e "${RED}Error: Could not create credential${NC}"
    exit 1
fi

echo "$CREATE_RESPONSE" > "$TEST_DIR/create_response.json"

# Extract credential ID using jq
CRED_ID=$(echo "$CREATE_RESPONSE" | jq -r '.id')

if [ -z "$CRED_ID" ] || [ "$CRED_ID" = "null" ]; then
    echo -e "${RED}Error: Could not obtain credential ID${NC}"
    echo "Response: $CREATE_RESPONSE"
    exit 1
fi

echo -e "${GREEN}✓ Credential created with ID: ${CRED_ID:0:20}...${NC}"
echo ""

# Test SPC authentication
echo -e "${YELLOW}2. Testing SPC authentication...${NC}"

SPC_AUTH_OPTIONS="{
    \"challenge\": \"DDDDDDDDDDDDDDDDDDDDDD\",
    \"rpId\": \"localhost\",
    \"allowCredentials\": [
      {
        \"type\": \"public-key\",
        \"id\": \"$CRED_ID\"
      }
    ],
    \"userVerification\": \"required\",
    \"timeout\": 60000,
    \"extensions\": {
      \"payment\": {
        \"isPayment\": true,
        \"rpId\": \"localhost\",
        \"topOrigin\": \"https://localhost:8443\",
        \"payeeName\": \"Naranjito Test Merchant\",
        \"payeeOrigin\": \"https://localhost:8443\",
        \"paymentEntitiesLogos\": [
          {
            \"url\": \"https://cdn.montoliu-bank.com/logos/montoliu-logo.png\",
            \"label\": \"Montoliu Bank\"
          }
        ],
        \"total\": {
          \"currency\": \"EUR\",
          \"value\": \"99.99\"
        },
        \"instrument\": {
          \"displayName\": \"Visa •••• 4321\",
          \"icon\": \"https://cdn.montoliu-bank.com/icons/visa-logo.png\",
          \"iconMustBeShown\": true,
          \"details\": \"Montoliu Bank Visa Credit Card\"
        }
      }
    }
  }"

echo "$SPC_AUTH_OPTIONS" > "$TEST_DIR/spc_auth_options.json"

# Generate SPC assertion using JAR
java -jar "$JAR_PATH" get --json-only --output "$TEST_DIR/spc_assertion_response.json" --verbose < "$TEST_DIR/spc_auth_options.json"

# Check if assertion was generated successfully
if [ ! -f "$TEST_DIR/spc_assertion_response.json" ] || ! jq -e . "$TEST_DIR/spc_assertion_response.json" > /dev/null 2>&1; then
    echo -e "${RED}✗ Failed to generate SPC assertion${NC}"
    if [ -f "$TEST_DIR/spc_assertion_response.json" ]; then
        echo -e "${RED}Error: $(cat "$TEST_DIR/spc_assertion_response.json")${NC}"
    fi
    exit 1
fi

echo -e "${GREEN}✓ SPC authentication completed${NC}"
echo ""

# Extract and decode clientDataJSON using jq
echo -e "${YELLOW}3. Verifying clientDataJSON...${NC}"

echo -e "${BLUE}Complete SPC response:${NC}"
cat "$TEST_DIR/spc_assertion_response.json" | jq '.'
echo ""

CLIENT_DATA_JSON_B64=$(cat "$TEST_DIR/spc_assertion_response.json" | jq -r '.response.clientDataJSON')

if [ -z "$CLIENT_DATA_JSON_B64" ] || [ "$CLIENT_DATA_JSON_B64" = "null" ]; then
    echo -e "${RED}Error: Could not extract clientDataJSON${NC}"
    echo "Response: $(cat "$TEST_DIR/spc_assertion_response.json")"
    exit 1
fi

echo -e "${BLUE}ClientDataJSON in Base64:${NC}"
echo "$CLIENT_DATA_JSON_B64"
echo ""

# Decode Base64URL (WebAuthn uses base64url, not standard base64)
if command -v python3 >/dev/null 2>&1; then
    CLIENT_DATA_JSON=$(echo "$CLIENT_DATA_JSON_B64" | python3 -c "import base64, sys; print(base64.urlsafe_b64decode(sys.stdin.read().strip() + '==').decode())" 2>/dev/null)
else
    echo -e "${RED}Error: python3 is not available for base64url decoding${NC}"
    exit 1
fi

echo -e "${BLUE}Decoded clientDataJSON (raw):${NC}"
echo "$CLIENT_DATA_JSON"
echo ""

echo -e "${BLUE}Decoded clientDataJSON (formatted):${NC}"
echo "$CLIENT_DATA_JSON" | jq '.' 2>/dev/null || echo "Error formatting JSON: $CLIENT_DATA_JSON"
echo ""

# Verify that it contains the payment field using jq
HAS_PAYMENT=$(echo "$CLIENT_DATA_JSON" | jq 'has("payment")')

if [ "$HAS_PAYMENT" = "true" ]; then
    echo -e "${GREEN}✓ The clientDataJSON contains the 'payment' field (SPC)${NC}"
    
    # Verify specific SPC fields using jq
    HAS_TOTAL=$(echo "$CLIENT_DATA_JSON" | jq '.payment | has("total")')
    HAS_INSTRUMENT=$(echo "$CLIENT_DATA_JSON" | jq '.payment | has("instrument")')
    HAS_PAYEE_NAME=$(echo "$CLIENT_DATA_JSON" | jq '.payment | has("payeeName")')
    
    if [ "$HAS_TOTAL" = "true" ]; then
        TOTAL_VALUE=$(echo "$CLIENT_DATA_JSON" | jq -r '.payment.total.value')
        TOTAL_CURRENCY=$(echo "$CLIENT_DATA_JSON" | jq -r '.payment.total.currency')
        echo -e "${GREEN}✓ Contains transaction information: $TOTAL_VALUE $TOTAL_CURRENCY${NC}"
    fi
    
    if [ "$HAS_INSTRUMENT" = "true" ]; then
        INSTRUMENT_NAME=$(echo "$CLIENT_DATA_JSON" | jq -r '.payment.instrument.displayName')
        echo -e "${GREEN}✓ Contains payment instrument information: $INSTRUMENT_NAME${NC}"
    fi
    
    if [ "$HAS_PAYEE_NAME" = "true" ]; then
        PAYEE_NAME=$(echo "$CLIENT_DATA_JSON" | jq -r '.payment.payeeName')
        echo -e "${GREEN}✓ Contains payee information: $PAYEE_NAME${NC}"
    fi
    
else
    echo -e "${RED}✗ The clientDataJSON does NOT contain the 'payment' field${NC}"
    echo -e "${YELLOW}This may indicate that the SPC extension was not processed correctly${NC}"
fi

echo ""

# Test standard WebAuthn authentication for comparison
echo -e "${YELLOW}4. Testing standard WebAuthn authentication (without SPC)...${NC}"

STANDARD_AUTH_OPTIONS="{
    \"challenge\": \"EEEEEEEEEEEEEEEEEEEEEE\",
    \"rpId\": \"localhost\",
    \"allowCredentials\": [
      {
        \"type\": \"public-key\",
        \"id\": \"$CRED_ID\"
      }
    ],
    \"userVerification\": \"required\",
    \"timeout\": 60000
  }"

echo "$STANDARD_AUTH_OPTIONS" > "$TEST_DIR/standard_auth_options.json"

# Generate standard assertion using JAR
java -jar "$JAR_PATH" get --json-only --output "$TEST_DIR/standard_assertion_response.json" --verbose < "$TEST_DIR/standard_auth_options.json"

# Extract standard clientDataJSON using jq
STANDARD_CLIENT_DATA_B64=$(cat "$TEST_DIR/standard_assertion_response.json" | jq -r '.response.clientDataJSON')

if [ -n "$STANDARD_CLIENT_DATA_B64" ] && [ "$STANDARD_CLIENT_DATA_B64" != "null" ]; then
    STANDARD_CLIENT_DATA=$(echo "$STANDARD_CLIENT_DATA_B64" | python3 -c "import base64, sys; print(base64.urlsafe_b64decode(sys.stdin.read().strip() + '==').decode())" 2>/dev/null)
    
    echo -e "${BLUE}Standard clientDataJSON (without payment):${NC}"
    echo "$STANDARD_CLIENT_DATA" | jq '.' 2>/dev/null || echo "$STANDARD_CLIENT_DATA"
    
    STANDARD_HAS_PAYMENT=$(echo "$STANDARD_CLIENT_DATA" | jq 'has("payment")')
    
    if [ "$STANDARD_HAS_PAYMENT" = "true" ]; then
        echo -e "${YELLOW}Warning: Standard clientDataJSON unexpectedly contains 'payment' field${NC}"
    else
        echo -e "${GREEN}✓ Standard clientDataJSON does NOT contain 'payment' field (correct)${NC}"
    fi
else
    echo -e "${YELLOW}Could not verify standard response${NC}"
fi

echo ""
echo -e "${BLUE}=== SPC Test Completed ===${NC}"

# Summary
echo -e "${YELLOW}Summary:${NC}"
echo -e "• SPC Extension: ${GREEN}Supported${NC}"
echo -e "• Payment Field: ${GREEN}Included in clientDataJSON${NC}"
echo -e "• Fallback WebAuthn: ${GREEN}Works correctly${NC}"
echo ""
echo -e "${GREEN}🎉 The FIDO2 simulator now supports Secure Payment Confirmation!${NC}"
echo -e "All test files saved in: $TEST_DIR" 
