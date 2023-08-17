package uk.gov.communities.delta.helper

import uk.gov.communities.delta.auth.services.LdapUser

fun testLdapUser(
    dn: String = "dn",
    cn: String = "cn",
    memberOfCNs: List<String> = emptyList(),
    email: String? = "email",
    deltaTOTPSecret: String? = null,
    name: String = "Test User",
    accountEnabled: Boolean = true,
) = LdapUser(dn, cn, memberOfCNs, email, deltaTOTPSecret, name, accountEnabled)
