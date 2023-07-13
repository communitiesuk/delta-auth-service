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

## Example requests

Replace `<delta-app-password>` with the value of delta-website-ldap-password-test from AWS Secrets Manager.

```shell
curl -X POST 'http://localhost:8088/auth-internal/service-user/generate-saml-token' \
  -u 'delta.app:<delta-app-password>' \
  --header 'Delta-Client: marklogic:dev-marklogic-client-secret'
```

## GOV.UK Frontend

For simplicity's sake we use the GOV.UK Frontend design system by copying the precompiled files rather than using npm.

To update them:

* See <https://frontend.design-system.service.gov.uk/install-using-precompiled-files/> for general instructions and download links
* Find and replace in the CSS file to change links to "/assets/" to "/auth-external/static/assets/"
* Update the version numbers linked from the HTML header
