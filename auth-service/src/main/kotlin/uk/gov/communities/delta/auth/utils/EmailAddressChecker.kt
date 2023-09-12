package uk.gov.communities.delta.auth.utils

import Organisation
import OrganisationService
import java.util.*


class EmailAddressChecker(private val organisationService: OrganisationService) {

    fun hasValidEmailFormat(email: String): Boolean {
        if (email.count { it == '@' } != 1) return false
        val emailRegex = """^[\w-+.]+@([\w-]+\.)+[\w-]{2,4}$""".toRegex()
        return emailRegex.matches(email)
    }

    suspend fun hasKnownNotRetiredDomain(email: String): Boolean {
        if (email.count { it == '@' } != 1) return false
        val domain = emailToDomain(email)
        val organisations = organisationService.findAllByDomain(domain)
        return organisations.any { organisation: Organisation -> !organisation.retired }
    }
}

fun emailToDomain(email: String): String {
    return email.split("@")[1].lowercase(Locale.getDefault())
}
