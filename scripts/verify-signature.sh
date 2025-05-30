#!/bin/bash

# Script para verificar externamente las firmas FIDO2 generadas
# Útil para validar contra implementaciones de referencia

set -e

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${BLUE}=== $1 ===${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

# Función para verificar dependencias
check_dependencies() {
    print_header "Verificando dependencias"
    
    local deps_ok=true
    
    if ! command -v openssl &> /dev/null; then
        print_error "OpenSSL no está instalado"
        deps_ok=false
    else
        print_success "OpenSSL encontrado: $(openssl version)"
    fi
    
    if ! command -v base64 &> /dev/null; then
        print_error "base64 no está disponible"
        deps_ok=false
    else
        print_success "base64 encontrado"
    fi
    
    if ! command -v sha256sum &> /dev/null && ! command -v shasum &> /dev/null; then
        print_error "Herramienta SHA256 no encontrada"
        deps_ok=false
    else
        if command -v sha256sum &> /dev/null; then
            print_success "sha256sum encontrado"
        else
            print_success "shasum encontrado"
        fi
    fi
    
    if [ "$deps_ok" = false ]; then
        print_error "Faltan dependencias requeridas"
        exit 1
    fi
}

# Función para calcular SHA256
calculate_sha256() {
    local input="$1"
    
    if command -v sha256sum &> /dev/null; then
        echo -n "$input" | sha256sum | cut -d' ' -f1
    else
        echo -n "$input" | shasum -a 256 | cut -d' ' -f1
    fi
}

# Función para verificar estructura del clientData
verify_client_data_structure() {
    local client_data="$1"
    print_header "Verificando estructura del Client Data"
    
    # Verificar que es JSON válido
    if echo "$client_data" | jq . > /dev/null 2>&1; then
        print_success "Client Data es JSON válido"
    else
        print_error "Client Data no es JSON válido"
        return 1
    fi
    
    # Verificar campos requeridos
    local type=$(echo "$client_data" | jq -r '.type // empty')
    local challenge=$(echo "$client_data" | jq -r '.challenge // empty')
    local origin=$(echo "$client_data" | jq -r '.origin // empty')
    
    if [ "$type" = "webauthn.get" ]; then
        print_success "Campo 'type' correcto: $type"
    else
        print_error "Campo 'type' incorrecto: $type (esperado: webauthn.get)"
        return 1
    fi
    
    if [ -n "$challenge" ]; then
        print_success "Campo 'challenge' presente: ${challenge:0:20}..."
    else
        print_error "Campo 'challenge' faltante"
        return 1
    fi
    
    if [[ "$origin" =~ ^https:// ]]; then
        print_success "Campo 'origin' correcto: $origin"
    else
        print_error "Campo 'origin' incorrecto: $origin (debe ser https://)"
        return 1
    fi
    
    return 0
}

# Función para verificar longitud de authenticator data
verify_authenticator_data() {
    local auth_data_hex="$1"
    print_header "Verificando Authenticator Data"
    
    local length=$((${#auth_data_hex} / 2))
    
    if [ $length -ge 37 ]; then
        print_success "Longitud de Authenticator Data correcta: $length bytes (mínimo: 37)"
    else
        print_error "Longitud de Authenticator Data incorrecta: $length bytes (mínimo: 37)"
        return 1
    fi
    
    # Extraer componentes
    local rp_id_hash=${auth_data_hex:0:64}  # 32 bytes = 64 chars hex
    local flags=${auth_data_hex:64:2}       # 1 byte = 2 chars hex
    local sign_count=${auth_data_hex:66:8}  # 4 bytes = 8 chars hex
    
    print_success "RP ID Hash: $rp_id_hash"
    print_success "Flags: 0x$flags"
    print_success "Sign Count: 0x$sign_count"
    
    # Verificar flag UP (User Present)
    local flags_decimal=$((16#$flags))
    if [ $((flags_decimal & 1)) -eq 1 ]; then
        print_success "Flag UP (User Present) está activo"
    else
        print_warning "Flag UP (User Present) no está activo"
    fi
    
    return 0
}

# Función para verificar firma con OpenSSL
verify_signature_openssl() {
    local auth_data_hex="$1"
    local client_data_json="$2"
    local signature_hex="$3"
    local public_key_file="$4"
    
    print_header "Verificando firma con OpenSSL"
    
    if [ ! -f "$public_key_file" ]; then
        print_error "Archivo de clave pública no encontrado: $public_key_file"
        return 1
    fi
    
    # Calcular hash del client data
    local client_data_hash=$(echo -n "$client_data_json" | openssl dgst -sha256 -binary | xxd -p -c 256)
    print_success "Client Data Hash: $client_data_hash"
    
    # Construir data to sign
    local data_to_sign_hex="${auth_data_hex}${client_data_hash}"
    print_success "Data to Sign: ${data_to_sign_hex:0:60}..."
    
    # Crear archivos temporales
    local temp_dir=$(mktemp -d)
    local data_file="$temp_dir/data_to_sign.bin"
    local sig_file="$temp_dir/signature.bin"
    
    # Convertir hex a binario
    echo "$data_to_sign_hex" | xxd -r -p > "$data_file"
    echo "$signature_hex" | xxd -r -p > "$sig_file"
    
    # Verificar firma
    if openssl dgst -sha256 -verify "$public_key_file" -signature "$sig_file" "$data_file" > /dev/null 2>&1; then
        print_success "Firma verificada correctamente con OpenSSL"
        local result=0
    else
        print_error "Firma NO válida según OpenSSL"
        local result=1
    fi
    
    # Limpiar archivos temporales
    rm -rf "$temp_dir"
    
    return $result
}

# Función principal
main() {
    print_header "Verificador de Firmas FIDO2"
    
    check_dependencies
    
    # Parámetros de entrada
    local auth_data_hex="$1"
    local client_data_json="$2"
    local signature_hex="$3"
    local public_key_file="$4"
    
    if [ $# -ne 4 ]; then
        echo "Uso: $0 <authenticator_data_hex> <client_data_json> <signature_hex> <public_key_file>"
        echo ""
        echo "Ejemplo:"
        echo "$0 'deadbeef...' '{\"type\":\"webauthn.get\",...}' 'abcdef...' key.pem"
        exit 1
    fi
    
    # Ejecutar verificaciones
    local all_ok=true
    
    if ! verify_client_data_structure "$client_data_json"; then
        all_ok=false
    fi
    
    if ! verify_authenticator_data "$auth_data_hex"; then
        all_ok=false
    fi
    
    if ! verify_signature_openssl "$auth_data_hex" "$client_data_json" "$signature_hex" "$public_key_file"; then
        all_ok=false
    fi
    
    # Resultado final
    echo ""
    if [ "$all_ok" = true ]; then
        print_success "Todas las verificaciones pasaron correctamente"
        exit 0
    else
        print_error "Algunas verificaciones fallaron"
        exit 1
    fi
}

# Verificar si se está ejecutando directamente
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    main "$@"
fi
