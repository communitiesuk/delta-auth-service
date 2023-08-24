val ktorVersion = "2.3.2"
val kotlinVersion = "1.8.22"

plugins {
    kotlin("jvm") version "1.8.22"
    id("io.ktor.plugin") version "2.3.2"
    id("org.jetbrains.kotlin.plugin.serialization") version "1.8.22"
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
}

dependencies {
    implementation("io.ktor:ktor-server-core-jvm:$ktorVersion")
    implementation("io.ktor:ktor-server-auth-jvm:$ktorVersion")
    implementation("io.ktor:ktor-server-call-logging-jvm:$ktorVersion")
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
    implementation("io.micrometer:micrometer-registry-cloudwatch2:1.11.2")

    //Emails
    implementation("com.sun.mail:javax.mail:1.6.2")

    // Logging
    implementation("ch.qos.logback:logback-classic:1.4.8")
    implementation("net.logstash.logback:logstash-logback-encoder:7.4") // Structured log encoder
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-slf4j:1.7.2")

    // OpenSAML
    implementation("org.opensaml:opensaml-core:4.0.1")
    implementation("org.opensaml:opensaml-saml-impl:4.0.1")

    // Database
    implementation("org.postgresql:postgresql:42.6.0")
    implementation("com.zaxxer:HikariCP:5.0.1") // Connection pool
    implementation("org.flywaydb:flyway-core:9.20.1") // Migrations

    testImplementation("io.ktor:ktor-server-tests-jvm:$ktorVersion")
    testImplementation("org.jetbrains.kotlin:kotlin-test-junit:$kotlinVersion")
    testImplementation("io.ktor:ktor-client-mock:$ktorVersion")
    testImplementation("io.mockk:mockk:1.13.5")
}

// Migrations are run by the application on startup, or on first use of the database in Development mode.
// Extra task to run Flyway migrations without (re)starting the app.
task("migrate", JavaExec::class) {
    mainClass.set("uk.gov.communities.delta.auth.services.DbPoolKt")
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
