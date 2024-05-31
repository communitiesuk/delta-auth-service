package uk.gov.communities.delta.helper

import uk.gov.communities.delta.auth.repositories.LdapUser
import java.time.Instant

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
    mangledDeltaObjectGuid: String? = null,
    javaUUIDObjectGuid: String? = "00112233-4455-6677-8899-aabbccddeeff",
    telephone: String? = null,
    mobile: String? = null,
    positionInOrganisation: String? = null,
    reasonForAccess: String? = null,
    comment: String? = null,
    notificationStatus: String = "active",
    passwordLastSet: Instant? = Instant.EPOCH
) = LdapUser(
    dn, cn, memberOfCNs, email, deltaTOTPSecret, firstName, lastName, fullName, accountEnabled,
    mangledDeltaObjectGuid, javaUUIDObjectGuid, telephone, mobile, positionInOrganisation,
    reasonForAccess, comment, notificationStatus, passwordLastSet
)
