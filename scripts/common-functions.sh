#!/bin/bash

# Common functions for FIDO2 WebAuthn.io tutorial scripts
# This file contains shared functionality for dependency checking and JAR detection

# Colors for better output readability
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to check if a command exists
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

# Function to verify all required dependencies
check_dependencies() {
    echo -e "${BLUE}=== Verificando dependencias necesarias ===${NC}"
    
    local all_ok=0
    
    # Check Java
    if ! check_command java "Java"; then
        all_ok=1
        echo -e "${YELLOW}Instrucciones para instalar Java:${NC}"
        echo "  Windows: Descarga JDK desde https://adoptium.net/"
        echo "  macOS: brew install --cask temurin"
        echo "  Linux: sudo apt install default-jdk"
        echo ""
    fi
    
    # Check curl
    if ! check_command curl "curl"; then
        all_ok=1
        echo -e "${YELLOW}Instrucciones para instalar curl:${NC}"
        echo "  Windows: winget install cURL"
        echo "  macOS: brew install curl"
        echo "  Linux: sudo apt install curl"
        echo ""
    fi
    
    # Check jq
    if ! check_command jq "jq"; then
        all_ok=1
        echo -e "${YELLOW}Instrucciones para instalar jq:${NC}"
        echo "  Windows: winget install jqlang.jq"
        echo "  macOS: brew install jq"
        echo "  Linux: sudo apt install jq"
        echo ""
    fi
    
    # Exit if any dependency is missing
    if [ $all_ok -eq 1 ]; then
        echo -e "${RED}Error: Faltan dependencias necesarias. Por favor, instale las herramientas faltantes e intente de nuevo.${NC}"
        exit 1
    fi
}

# Function to find the most recent JAR file
find_latest_jar() {
    local target_dir="target"
    
    # Check if target directory exists
    if [ ! -d "$target_dir" ]; then
        echo -e "${RED}Error: Target directory not found${NC}"
        echo -e "Please build the project using: mvn clean package"
        return 1
    fi
    
    # Find the most recent JAR file by modification date
    local latest_jar=$(ls -t "$target_dir"/fido2-client-simulator-*.jar 2>/dev/null | head -n 1)
    
    if [ -z "$latest_jar" ]; then
        echo -e "${RED}Error: No FIDO2 client simulator JAR files found in $target_dir${NC}"
        echo -e "Please build the project using: mvn clean package"
        return 1
    fi
    
    echo "$latest_jar"
    return 0
}

# Function to locate and validate the JAR file
setup_jar_path() {
    echo -e "${BLUE}=== Locating JAR file ===${NC}"
    JAR_PATH=$(find_latest_jar)
    
    if [ $? -ne 0 ] || [ -z "$JAR_PATH" ]; then
        exit 1
    fi
    
    echo -e "${GREEN}✓ Found JAR file: $JAR_PATH${NC}"
    
    # Verify the JAR file exists and is readable
    if [ ! -f "$JAR_PATH" ] || [ ! -r "$JAR_PATH" ]; then
        echo -e "${RED}Error: JAR file not accessible at $JAR_PATH${NC}"
        echo -e "Please check file permissions or rebuild the project using: mvn clean package"
        exit 1
    fi
    
    # Export JAR_PATH so it's available to the calling script
    export JAR_PATH
}

# Main setup function that checks everything
setup_environment() {
    check_dependencies
    setup_jar_path
} 
