# Delta Auth Service

Part of the Delta system to handle auth related logic and abstract the underlying Active Directory user store.

## Structure

* terraform/ - infrastructure code for this project, it depends on the VPC etc. defined in <https://github.com/communitiesuk/delta-common-infrastructure>, and we follow the same patterns
* auth-service/ - Ktor application
