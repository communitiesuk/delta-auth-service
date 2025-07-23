FROM amazoncorretto:24 as builder
WORKDIR /app

COPY gradlew build.gradle.kts gradle.properties settings.gradle.kts ./
COPY gradle gradle
# Use to download dependencies and make better use of the build cache, useful for running in Docker locally
# Left commented out as it's built from a clean slate in CI anyway
# RUN chmod +x gradlew && ./gradlew build || return 0

COPY src src
RUN ./gradlew buildFatJar

FROM amazoncorretto:24
WORKDIR /app

RUN yum install wget openssl -y

RUN mkdir -p /root/.postgresql && \
    wget https://truststore.pki.rds.amazonaws.com/eu-west-1/eu-west-1-bundle.pem -O /root/.postgresql/ca-bundle.pem

COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh
COPY --from=builder /app/build/libs/auth-all.jar .

ENTRYPOINT ["bash", "/app/entrypoint.sh"]
