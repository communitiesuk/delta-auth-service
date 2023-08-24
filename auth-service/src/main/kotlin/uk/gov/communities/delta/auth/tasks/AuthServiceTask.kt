package uk.gov.communities.delta.auth.tasks

abstract class AuthServiceTask(val name: String) {
    abstract suspend fun execute()
}
