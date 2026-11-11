#!/usr/bin/env bash
set -euo pipefail

output_dir="${1:-experiment/local/certs}"
mkdir -p "$output_dir"
cd "$output_dir"

openssl ecparam -name prime256v1 -genkey -noout -out caKey.pem
openssl req -x509 -new -key caKey.pem -sha256 -days 30 \
  -subj "/CN=Artifact Test CA" -out caCert.pem

openssl ecparam -name prime256v1 -genkey -noout -out serverKey.pem
openssl req -new -key serverKey.pem -subj "/CN=responder" -out server.csr
printf '%s\n' 'basicConstraints=CA:FALSE' 'keyUsage=digitalSignature' \
  'extendedKeyUsage=serverAuth' 'subjectAltName=DNS:responder' > server-ext.cnf
openssl x509 -req -in server.csr -CA caCert.pem -CAkey caKey.pem \
  -CAcreateserial -out serverCert.pem -days 30 -sha256 -extfile server-ext.cnf

openssl ecparam -name prime256v1 -genkey -noout -out clientKey.pem
openssl req -new -key clientKey.pem -subj "/CN=initiator" -out client.csr
printf '%s\n' 'basicConstraints=CA:FALSE' 'keyUsage=digitalSignature' \
  'extendedKeyUsage=clientAuth' 'subjectAltName=DNS:initiator' > client-ext.cnf
openssl x509 -req -in client.csr -CA caCert.pem -CAkey caKey.pem \
  -CAcreateserial -out clientCert.pem -days 30 -sha256 -extfile client-ext.cnf

chmod 600 ./*Key.pem
echo "PASS: generated disposable test credentials in $output_dir"
