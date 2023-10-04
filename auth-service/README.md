# Auth service

## Setup

* Requires Java 17
* Forward localhost:2389 to port 389 of the test environment Active Directory,
  see the delta-common-infrastructure repository for details of the bastion host,
  and delta for port forwarding commands
* Copy `.env.template` to `.env` and fill it in as instructed in that file
* Postgres, by default on port 5438, use `docker compose up -d`
* Follow the steps in delta repository README `delta\biz-tier-app\delta\README.md` to set up LDAPS certificate

## Run

* Start with `./gradlew run` (to run locally with AWS metrics run through aws-vault
  as `aws-vault exec <profile> -- .\gradlew.bat run` and set environment variable AUTH_METRICS_NAMESPACE to e.g. "
  localYourName/AuthService")

Alternatively open in IntelliJ, add this folder as a Gradle module, then create a new Ktor run configuration
with `uk.gov.communities.delta.auth.ApplicationKt` as the main class and environment variables set from `.env`. (See
below image for an example)

![img.png](runConfiguration.png)

Set the `io.ktor.development` property to `true` (`-Dio.ktor.development=true` JVM arg) to enable development mode (
faster restarts, reloading of templates).

## Tests

* `./gradlew test`
* Postgres must be running

## Example requests

### Generate SAML token

Replace `<delta-app-password>` with the value of delta-website-ldap-password-test from AWS Secrets Manager.

```shell
curl -X POST 'http://localhost:8088/auth-internal/service-user/generate-saml-token' \
  -u 'delta.app:<delta-app-password>' \
  --header 'Delta-Client: marklogic:dev-marklogic-client-secret'
```

### OAuth flow

Users sign in to Delta via the auth service.
We use the [OAuth 2 Authorization Code flow](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1)
which allows us to use a standard OAuth client library in Delta.

#### 1. Login Redirect

Delta redirects unauthenticated users to the auth
service `http://localhost:8088/delta/login?response_type=code&client_id=delta-website&state=1234` (
use `client-id=delta-website-dev` for local dev).

The user will be shown a login page and provide a username and password as a standard form submission.

#### 2. Authorization code redirect

The user's credentials are validated by performing an LDAP bind against AD.
The auth service will then redirect the user back to delta with an authorization code
`http://delta/login/oauth2/redirect?code=4321&state=1234`.

#### 3. Code exchange

Delta uses the internal API to exchange that code for a token.
Note that the code is only valid for a short time.

```sh
curl -X POST 'http://localhost:8088/auth-internal/token' \
  -d "code=4321&client_id=delta-website&client_secret=dev-delta-website-client-secret"
```

The auth service will respond with an access token and information about the user.

```json
{
  "access_token": "ABC123",
  "delta_ldap_user": {
    "cn": "delta.admin",
    "memberOfCNs": [
      "datamart-delta-dataset-admins",
      "datamart-delta-data-providers"
    ],
    "email": "delta.admin",
    "deltaTOTPSecret": "ABC987",
    "name": "Delta Admin"
  },
  "saml_token": "token",
  "expires_at_epoch_second": 1690327542,
  "token_type": "bearer",
  "expires_in": "43200"
}
```

#### 4. Refresh user info

If required Delta can get updated user info without repeating the login flow using
the `/auth-internal/bearer/user-info` endpoint.

```sh
curl 'http://localhost:8088/auth-internal/bearer/user-info' \
  --header 'Authorization: Bearer ABC123' \
  --header 'Delta-Client: delta-website:dev-delta-website-client-secret'
```

The response is similar to above, though the access token is not repeated.

## GOV.UK Frontend

We use the [GOV.UK Frontend](https://frontend.design-system.service.gov.uk/) design system.

For simplicity, we copy the precompiled files rather than using npm.

To update them:

* See <https://frontend.design-system.service.gov.uk/install-using-precompiled-files/> for general instructions and
  download links
* Download the updated bundle and replace the existing files, following the folder structure in this repo
* Find and replace in the CSS file to change links to "/assets/" to "/static/assets/"
* Update the version numbers linked from the HTML header

## Scheduled tasks

You can run a task locally by setting the RUN_TASK environment variable and using the "runTask" gradle task, for example

```shell
RUN_TASK=DeleteOldAuthCodes ./gradlew runTask
```

In hosted environments scheduled tasks are run using AWS EventBridge Scheduler,
which invokes an ECS task with the RUN_TASK environment variable set, and the
Docker [entrypoint script](./entrypoint.sh)
will execute the task instead of the application.
