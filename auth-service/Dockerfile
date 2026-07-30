FROM amazoncorretto:17-al2023 AS builder
WORKDIR /app

RUN dnf install -y findutils-4.8.0-2.amzn2023.0.2 && \
    dnf clean all

COPY gradlew build.gradle.kts gradle.properties settings.gradle.kts ./
COPY gradle gradle
# Use to download dependencies and make better use of the build cache, useful for running in Docker locally
# Left commented out as it's built from a clean slate in CI anyway
# RUN chmod +x gradlew && ./gradlew build || return 0

COPY src src
RUN ./gradlew buildFatJar

FROM amazoncorretto:17-al2023-headless
WORKDIR /app

RUN dnf install -y \
        openssl-3.5.5-1.amzn2023.0.5 \
        wget-1.21.3-1.amzn2023.0.4 && \
    dnf clean all

ENV JAVA_TRUSTSTORE_PATH=/app/certs/cacerts \
    JAVA_TOOL_OPTIONS="-Djavax.net.ssl.trustStore=/app/certs/cacerts -Djavax.net.ssl.trustStorePassword=changeit"

RUN mkdir -p /app/certs && \
    cp --dereference "${JAVA_HOME}/lib/security/cacerts" "${JAVA_TRUSTSTORE_PATH}" && \
    chmod 0644 "${JAVA_TRUSTSTORE_PATH}" && \
    chown -R 10001:10001 /app/certs

COPY --chown=10001:10001 certs/rds-ca-bundle.pem /app/certs/rds-ca-bundle.pem
COPY --chown=10001:10001 entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh
COPY --from=builder --chown=10001:10001 /app/build/libs/auth-all.jar .

USER 10001:10001
ENTRYPOINT ["bash", "/app/entrypoint.sh"]
