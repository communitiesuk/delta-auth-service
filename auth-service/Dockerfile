FROM amazoncorretto:17 as builder
WORKDIR /app

COPY gradlew build.gradle.kts gradle.properties settings.gradle.kts ./
COPY gradle gradle
# Build will fail, but will download dependencies
RUN chmod +x gradlew && ./gradlew build || return 0

COPY src src
RUN ./gradlew buildFatJar

FROM amazoncorretto:17
WORKDIR /app

COPY --from=builder /app/build/libs/auth-all.jar .

ENTRYPOINT ["java", "-jar", "auth-all.jar"]
