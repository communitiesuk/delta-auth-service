package uk.gov.communities.delta.helper

import uk.gov.communities.delta.auth.services.LdapUser

fun testLdapUser(
    dn: String = "dn",
    cn: String = "cn",
    memberOfCNs: List<String> = emptyList(),
    email: String? = "email",
    deltaTOTPSecret: String? = null,
    firstName: String = "Test",
    lastName: String = "Surname",
    fullName: String = "Test Surname",
    accountEnabled: Boolean = true,
    mangledDeltaObjectGuid: String = "mangled-id",
    telephone: String? = null,
    mobile: String? = null,
    positionInOrganisation: String? = null,
    reasonForAccess: String? = null,
    comment: String? = null,
) = LdapUser(
    dn, cn, memberOfCNs, email, deltaTOTPSecret, firstName, lastName, fullName, accountEnabled,
    mangledDeltaObjectGuid, telephone, mobile, positionInOrganisation, reasonForAccess, comment
)
