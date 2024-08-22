package uk.gov.communities.delta.auth.utils

import jakarta.mail.internet.InternetAddress
import uk.gov.communities.delta.auth.config.LDAPConfig
import uk.gov.communities.delta.auth.services.Organisation
import java.util.*


class EmailAddressChecker {

    fun hasValidFormat(email: String): Boolean {
        if (email.count { it == '@' } != 1) return false

        try {
            // Otherwise jakarta.mail will throw an exception later when we attempt to send an email
            InternetAddress(email).validate()
        } catch (e: Exception) {
            return false
        }

        val cn = LDAPConfig.emailToCN(email)
        return LDAPConfig.VALID_EMAIL_REGEX.matches(email) && LDAPConfig.VALID_USER_CN_REGEX.matches(cn)
    }

    fun hasKnownNotRetiredDomain(organisations: List<Organisation>): Boolean {
        return organisations.any { organisation: Organisation -> !organisation.retired }
    }
}

fun emailToDomain(email: String): String {
    return email.split("@")[1].lowercase(Locale.getDefault())
}
