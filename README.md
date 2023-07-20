# Delta Auth Service

Part of the Delta system to handle auth related logic and abstract the underlying Active Directory (AD) user store.

## Structure

* terraform/ - infrastructure code for this project, it depends on the VPC etc. defined in <https://github.com/communitiesuk/delta-common-infrastructure>, and we follow the same patterns
* auth-service/ - Ktor application

## Functionality

Currently used to:

1. Generate SAML tokens for use by MarkLogic XQuery code to allow it to authenticate send requests to Orbeon
2. Act as an OAuth 2 server for Delta, hosting the login page and handling communication with AD
