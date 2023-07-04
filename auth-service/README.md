# Auth service

## Setup

* Requires Java 17
* Forward localhost:2389 to port 389 of the test environment Active Directory,
  see the delta-common-infrastructure repository for details of the bastion host,
  and delta for port forwarding commands

## Run

* Start with `./gradlew run`

Alternatively open in IntelliJ, add this folder as a Gradle module, then create a new Ktor run configuration
with `uk.gov.communities.delta.auth.ApplicationKt` as the main class.

## Tests

* `./gradlew test`
