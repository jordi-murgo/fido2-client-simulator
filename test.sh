#!/bin/bash

echo "================"
echo "Remove old files"
echo "================"
rm -f fido2_metadata.json
rm -f fido2_keystore.p12

echo
echo "================"
echo "Create operation"
echo "================"
cat create_options.json
echo "================"
echo "java -jar target/fido2-client-simulator-1.0-SNAPSHOT.jar create --file create_options.json" 
java -jar target/fido2-client-simulator-1.0-SNAPSHOT.jar create --file create_options.json || exit 1

echo
echo "================"
echo "FIDO2 Keystore"
echo "================"
keytool -list -keystore fido2_keystore.p12 -storetype PKCS12 -storepass changeit || exit 1

echo
echo "================"
echo "FIDO2 Metadata"
echo "================"
cat fido2_metadata.json

echo
echo "================"
echo "Get operation"
echo "================"
cat get_options_notcredentials.json
echo "================"
echo "java -jar target/fido2-client-simulator-1.0-SNAPSHOT.jar get --file get_options_notcredentials.json"
java -jar target/fido2-client-simulator-1.0-SNAPSHOT.jar get --file get_options_notcredentials.json || exit 1
