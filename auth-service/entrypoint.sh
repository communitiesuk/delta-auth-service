#!/bin/bash
set -ex

if [[ -v CA_S3_URL ]]; then
  wget "${CA_S3_URL}" -O /tmp/dluhcldapsca.crt
  openssl x509 -inform der -in /tmp/dluhcldapsca.crt -outform pem -out /tmp/dluhcldapsca.pem
  keytool -import -cacerts -alias dluhcldapsca -file /tmp/dluhcldapsca.pem -noprompt -storepass changeit
fi

java -jar auth-all.jar
