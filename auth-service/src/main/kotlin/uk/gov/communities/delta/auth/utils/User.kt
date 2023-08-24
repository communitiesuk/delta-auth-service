package uk.gov.communities.delta.auth.utils

import com.google.common.base.Strings
import java.util.*

class User(
    val id: String?,
    val organisationIds: List<String?>,
    val systemRoles: List<Any?>,
    val externalRoles: List<Any?>,
    val accessGroups: List<Any?>,
    val isEnabled: Boolean,
    val isDeltaUser: Boolean,
    val isDeltaAdmin: Boolean,
    val uniqueIdentifier: String? = null,
    val firstName: String?,
    val lastName: String?,
    val email: String?,
    val telephone: String? = "",
    val mobile: String? = "",
    val position: String? = "",
    val reasonForAccess: String? = "",
//      val displayName: String?, TODO - is this needed - if so remove get from below/make kotlin happy
    val comment: String? = "",
) {
//    TODO - workout what this actually needs here
//     - most of this information is only relevant for admin creation which is not yet being moved
//     - are the below functions used?

    fun isMemberOfOrganisation(orgId: String?): Boolean {
        return organisationIds.contains(orgId)
    }

    fun findPrimaryOrganisationId(): Optional<String?> {
        return organisationIds.stream().findFirst()
    }

    fun getDisplayName() = (Strings.nullToEmpty(firstName) + " " + Strings.nullToEmpty(
        lastName
    )).trim { it <= ' ' }
}
