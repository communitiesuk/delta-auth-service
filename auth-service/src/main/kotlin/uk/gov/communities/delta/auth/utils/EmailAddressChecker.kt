package uk.gov.communities.delta.auth.utils

import OrganisationService
import java.util.*


class EmailAddressChecker(private val organisationService: OrganisationService) {

    fun hasValidEmailFormat(email: String): Boolean {
        if (email.count { it == '@' } != 1) return false
        val emailRegex = """^[\w-+.]+@([\w-]+\.)+[\w-]{2,4}$""".toRegex()
        return emailRegex.matches(email)
    }

    suspend fun hasKnownDomain(email: String): Boolean {
        if (email.count { it == '@' } != 1) return false
        val domain = emailToDomain(email)
        return organisationService.findAllByDomain(domain).isNotEmpty()
    }
}

fun emailToDomain(email: String): String {
    return email.split("@")[1].lowercase(Locale.getDefault())
}
