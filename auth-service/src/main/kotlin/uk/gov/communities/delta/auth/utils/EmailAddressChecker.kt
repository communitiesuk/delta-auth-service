package uk.gov.communities.delta.auth.utils

import uk.gov.communities.delta.auth.config.LDAPConfig
import uk.gov.communities.delta.auth.services.Organisation
import java.util.*


class EmailAddressChecker {

    fun hasValidFormat(email: String): Boolean {
        if (email.count { it == '@' } != 1) return false
        val cn = email.replace("@", "!")
        return LDAPConfig.VALID_EMAIL_REGEX.matches(email) && LDAPConfig.VALID_USERNAME_REGEX.matches(cn)
    }

    fun hasKnownNotRetiredDomain(organisations: List<Organisation>): Boolean {
        return organisations.any { organisation: Organisation -> !organisation.retired }
    }
}

fun emailToDomain(email: String): String {
    return email.split("@")[1].lowercase(Locale.getDefault())
}
