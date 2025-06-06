# FIDO2 Client Simulator - Colección de Postman

Esta colección de Postman proporciona una suite completa de pruebas para el FIDO2 Client Simulator operando en modo servidor HTTP.

## Configuración Inicial

1. **Importar la colección**: Importa el archivo `FIDO2_Client_Simulator.postman_collection.json` en Postman
2. **Configurar variables de entorno**:
   - `baseUrl`: URL base del servidor HTTP (por defecto: `http://localhost:8080`)
3. **Iniciar el servidor**: Ejecuta el simulador en modo servidor:

   ```bash
   java -jar target/fido2-client-simulator-1.3.0-SNAPSHOT.jar --listen 8080
   ```

## Estructura de la Colección

La colección está organizada en dos secciones principales:

### 1. Local Testing

Pruebas básicas contra el servidor HTTP local:

- **Create FIDO2 Credential**: Crea una nueva credencial FIDO2
- **Authenticate with FIDO2 Credential**: Autentica usando la credencial creada
- **Test Error Handling**: Prueba manejo de errores (404, 405, 400)
- **Get Server Information**: Obtiene información del servidor (versión, estado, endpoints, configuración)

### 2. WebAuthn.io Integration

Integración completa con webauthn.io usando nuestro servidor HTTP como autenticador FIDO2:

- **Get WebAuthn.io Registration Options**: Obtiene opciones de registro desde webauthn.io
- **Create Credential via HTTP Server**: Crea credencial usando nuestro servidor con las opciones de webauthn.io
- **Verify Registration with WebAuthn.io**: Verifica el registro en webauthn.io
- **Get WebAuthn.io Authentication Options**: Obtiene opciones de autenticación desde webauthn.io
- **Generate Assertion via HTTP Server**: Genera assertion usando nuestro servidor con las opciones de webauthn.io
- **Verify Authentication with WebAuthn.io**: Verifica la autenticación en webauthn.io

## Funcionalidades Avanzadas

### Variables de Entorno Automáticas

La colección gestiona automáticamente las siguientes variables:

- `credentialId` / `credentialIdBase64`: IDs de credenciales para pruebas locales
- `webauthn_registration_options`: Opciones de registro de webauthn.io
- `webauthn_credential`: Credencial creada para webauthn.io
- `webauthn_auth_options`: Opciones de autenticación de webauthn.io
- `webauthn_assertion`: Assertion generada para webauthn.io

### Scripts de Pre-request y Test

- **Pre-request scripts**: Preparan automáticamente los payloads usando datos de requests anteriores
- **Test scripts**: Validan respuestas, extraen datos importantes y los almacenan para requests posteriores
- **Logging**: Proporciona información detallada en la consola de Postman

### Flujo de Trabajo Automatizado

#### Flujo Local (Testing Básico)

1. Crear credencial → 2. Autenticar con credencial

#### Flujo WebAuthn.io (Integración Completa)

1. Obtener opciones de registro de webauthn.io
2. Crear credencial usando nuestro servidor HTTP
3. Verificar registro en webauthn.io
4. Obtener opciones de autenticación de webauthn.io
5. Generar assertion usando nuestro servidor HTTP
6. Verificar autenticación en webauthn.io

## Uso de la Colección

### Pruebas Locales Básicas

1. Ejecuta los requests en la carpeta "Local Testing" en orden
2. La colección extraerá automáticamente el credential ID y lo usará en la autenticación

### Integración con WebAuthn.io

1. Ejecuta los requests en la carpeta "WebAuthn.io Integration" en orden secuencial
2. Cada request usa datos del request anterior automáticamente
3. Los scripts de JavaScript manejan toda la transformación de datos

## Ejemplo de salida esperada

### Crear credencial (exitosa)

```
✓ Status code is 200
✓ Response contains credential data
✓ Store credential ID for next request
✓ Log credential information
```

### Autenticar credencial (exitosa)

```
✓ Status code is 200 (successful authentication)
✓ Response contains authentication data
✓ Log authentication result
```

### Integración WebAuthn.io (exitosa)

```
✓ Status code is 200
✓ Response contains registration options
✓ Store registration options
✓ Registration verified successfully on webauthn.io!
✓ Authentication verified successfully on webauthn.io!
```

### Información del servidor (exitosa)

```
✓ Status code is 200
✓ Response contains server information
✓ Server status is running
✓ All endpoints are documented
✓ CORS headers are present
✓ Log server information
```

## Manejo de Errores

La colección incluye pruebas específicas para:

- **404 Not Found**: Endpoints inválidos
- **405 Method Not Allowed**: Métodos HTTP no soportados
- **400 Bad Request**: Cuerpos de request vacíos o malformados
- **500 Internal Server Error**: Errores del servidor/handler

## Headers CORS

Todos los requests del servidor incluyen headers CORS apropiados:

- `Access-Control-Allow-Origin: *`
- `Access-Control-Allow-Methods: POST, OPTIONS`
- `Access-Control-Allow-Headers: Content-Type`

## Requisitos

- Postman (versión reciente con soporte para scripts de JavaScript)
- Java 11+ para ejecutar el servidor FIDO2
- Conexión a internet para las pruebas de webauthn.io

## Troubleshooting

### Error: "No registration options found"

Asegúrate de ejecutar primero "Get WebAuthn.io Registration Options" antes de crear la credencial.

### Error: "No credential found"

Para las pruebas locales, ejecuta "Create FIDO2 Credential" antes de la autenticación.
Para webauthn.io, asegúrate de completar todo el flujo de registro antes de la autenticación.

### Error de conexión al servidor

Verifica que el servidor FIDO2 esté ejecutándose en el puerto correcto:

```bash
java -jar target/fido2-client-simulator-1.3.0-SNAPSHOT.jar --listen 8080
```

### Problemas con webauthn.io

- Verifica que tengas conexión a internet
- Los headers `Origin: https://webauthn.io` son requeridos para las requests a webauthn.io
- webauthn.io puede tener límites de rate limiting

## Integración con CI/CD

Esta colección puede ejecutarse en entornos de CI/CD usando Newman:

```bash
# Instalar Newman
npm install -g newman

# Ejecutar la colección
newman run FIDO2_Client_Simulator.postman_collection.json \
  --environment tu_entorno.json \
  --reporters html,cli
```
