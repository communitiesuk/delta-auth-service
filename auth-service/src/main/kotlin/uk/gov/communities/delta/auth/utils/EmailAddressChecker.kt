package uk.gov.communities.delta.auth.utils

import uk.gov.communities.delta.auth.config.LDAPConfig
import uk.gov.communities.delta.auth.services.Organisation
import java.util.*


class EmailAddressChecker {

    fun hasValidEmailFormat(email: String): Boolean {
        if (email.count { it == '@' } != 1) return false

        val emailRegex = """^[\w-+.']+@([\w-']+\.)+[\w-]{2,4}$""".toRegex()
        val cn = email.replace("@", "!")
        return emailRegex.matches(email) && LDAPConfig.VALID_USERNAME_REGEX.matches(cn)
    }

    fun hasKnownNotRetiredDomain(email: String, organisations: List<Organisation>): Boolean {
        if (email.count { it == '@' } != 1) return false
        return organisations.any { organisation: Organisation -> !organisation.retired }
    }
}

fun emailToDomain(email: String): String {
    return email.split("@")[1].lowercase(Locale.getDefault())
}
