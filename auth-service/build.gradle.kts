val ktorVersion = "2.3.13"
val kotlinVersion = "2.2.0"
val flywayVersion = "11.11.0"

plugins {
    kotlin("jvm") version "2.2.0"
    id("io.ktor.plugin") version "3.3.2"
    id("org.jetbrains.kotlin.plugin.serialization") version "2.2.0"
}

group = "uk.gov.communities.delta.auth"
version = "0.0.1"
application {
    mainClass.set("uk.gov.communities.delta.auth.ApplicationKt")

    applicationDefaultJvmArgs = listOf("-Dio.ktor.development=true")
    // Run in the repository's root folder to match IntelliJ's behaviour
    // so that template reloading works for both (see Templating.kt)
    tasks.run.get().workingDir = rootProject.projectDir.parentFile
}

tasks {
    shadowJar {
        // Required for OpenSAML initialisation, it relies on aliasing config files in META-INF being merged
        mergeServiceFiles()
    }
}

repositories {
    mavenCentral()
    maven {
        // For OpenSAML, which is currently maintained by Shibboleth with new versions no longer being published to Maven Central
        url = uri("https://build.shibboleth.net/maven/releases/")
    }
}

dependencies {
    implementation("io.ktor:ktor-server-core-jvm:$ktorVersion")
    implementation("io.ktor:ktor-server-auth-jvm:$ktorVersion")
    implementation("io.ktor:ktor-server-call-id-jvm:$ktorVersion")
    implementation("io.ktor:ktor-server-content-negotiation-jvm:$ktorVersion")
    implementation("io.ktor:ktor-client-content-negotiation-jvm:$ktorVersion")
    implementation("io.ktor:ktor-serialization-kotlinx-json-jvm:$ktorVersion")
    implementation("io.ktor:ktor-client-java:$ktorVersion")
    implementation("io.ktor:ktor-server-netty-jvm:$ktorVersion")
    implementation("io.ktor:ktor-network-tls-certificates:$ktorVersion")
    implementation("io.ktor:ktor-server-status-pages-jvm:$ktorVersion")
    implementation("io.ktor:ktor-server-sessions-jvm:$ktorVersion")

    // HTML templating
    implementation("io.ktor:ktor-server-thymeleaf:$ktorVersion")
    implementation("io.ktor:ktor-server-thymeleaf-jvm:$ktorVersion")

    // Rate limiting
    implementation("io.ktor:ktor-server-rate-limit:$ktorVersion")
    implementation("io.ktor:ktor-server-forwarded-header:$ktorVersion")

    // Headers
    implementation("io.ktor:ktor-server-caching-headers-jvm:$ktorVersion")

    // Metrics
    implementation("io.ktor:ktor-server-metrics-micrometer:$ktorVersion")
    implementation("io.micrometer:micrometer-registry-cloudwatch2:1.15.2")

    // CORS
    implementation("io.ktor:ktor-server-cors:$ktorVersion")

    // Emails
    implementation("com.sun.mail:jakarta.mail:2.0.1")

    // Logging
    implementation("ch.qos.logback:logback-classic:1.5.18")
    implementation("net.logstash.logback:logstash-logback-encoder:8.1") // Structured log encoder
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-slf4j:1.10.2")

    // OpenSAML
    implementation("org.opensaml:opensaml-core:4.3.2")
    implementation("org.opensaml:opensaml-saml-impl:4.3.2")

    // Database
    implementation("org.postgresql:postgresql:42.7.7")
    implementation("com.zaxxer:HikariCP:7.0.2") // Connection pool
    implementation("org.flywaydb:flyway-core:$flywayVersion") // Migrations
    implementation("org.flywaydb:flyway-database-postgresql:$flywayVersion") // Migrations

    testImplementation("io.ktor:ktor-server-tests-jvm:$ktorVersion")
    testImplementation("org.jetbrains.kotlin:kotlin-test-junit:$kotlinVersion")
    testImplementation("io.ktor:ktor-client-mock:$ktorVersion")
    testImplementation("io.mockk:mockk:1.14.6")

    // Tracing - sending traces to AWS X-Ray via OpenTelemetry
    api(platform("io.opentelemetry.instrumentation:opentelemetry-instrumentation-bom-alpha:2.8.0-alpha"))
    implementation("io.opentelemetry:opentelemetry-api")
    implementation("io.opentelemetry:opentelemetry-sdk")
    implementation("io.opentelemetry:opentelemetry-extension-kotlin")
    implementation("io.opentelemetry:opentelemetry-exporter-otlp")
    testImplementation("io.opentelemetry:opentelemetry-exporter-logging")
    implementation("io.opentelemetry.instrumentation:opentelemetry-ktor-2.0")
    implementation("io.opentelemetry.instrumentation:opentelemetry-jdbc")

    implementation("io.opentelemetry.contrib:opentelemetry-aws-xray-propagator:1.39.0-alpha")
    implementation("io.opentelemetry.contrib:opentelemetry-aws-xray:1.39.0")
}

// Migrations are run by the application on startup, or on first use of the database in Development mode.
// Extra task to run Flyway migrations without (re)starting the app.
task("migrate", JavaExec::class) {
    mainClass.set("uk.gov.communities.delta.auth.repositories.DbPoolKt")
    classpath = sourceSets["main"].runtimeClasspath
}

fun JavaExec.readEnvFile() {
    val envFile = file(".env")
    if (envFile.exists()) {
        envFile.readLines().forEach {
            if (it.isNotEmpty() && !it.startsWith("#")) {
                val (key, value) = it.split("=")
                environment(key, value)
            }
        }
    }
}

task("runTask", JavaExec::class) {
    mainClass.set("uk.gov.communities.delta.auth.tasks.RunTaskMainKt")
    classpath = sourceSets["main"].runtimeClasspath
    readEnvFile()
}

tasks {
    "run"(JavaExec::class) {
        readEnvFile()
    }
}
