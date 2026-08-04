#!/bin/bash
set -e

function echo_json() {
  echo "{\"message\": \"$1\",\"level\": \"INFO\",\"logger_name\":\"DOCKER_ENTRYPOINT\"}"
}

echo_json "Entrypoint script starting"

if [[ -v CA_S3_URL ]]; then
  echo_json "Fetching CA Certificate from ${CA_S3_URL}"
  wget -q "${CA_S3_URL}" -O /tmp/dluhcldapsca.crt
  openssl x509 -inform der -in /tmp/dluhcldapsca.crt -outform pem -out /tmp/dluhcldapsca.pem
  keytool -importcert -keystore "${JAVA_TRUSTSTORE_PATH}" -alias dluhcldapsca \
    -file /tmp/dluhcldapsca.pem -noprompt -storepass changeit
  rm -f /tmp/dluhcldapsca.crt /tmp/dluhcldapsca.pem
fi

if [ -v RUN_TASK ]; then
    echo_json "RUN_TASK is set, starting task ${RUN_TASK}"
    java -cp auth-all.jar uk.gov.communities.delta.auth.tasks.RunTaskMainKt
    echo_json "Task complete, exiting"
    exit 0
fi

echo_json "Starting application"

java -jar auth-all.jar
