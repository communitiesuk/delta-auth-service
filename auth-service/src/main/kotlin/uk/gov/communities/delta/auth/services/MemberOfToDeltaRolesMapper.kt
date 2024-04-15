package uk.gov.communities.delta.auth.services

import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.LDAPConfig.Companion.DATAMART_DELTA_PREFIX
import uk.gov.communities.delta.auth.repositories.LdapUser

typealias MemberOfToDeltaRolesMapperFactory = (
    username: String,
    allOrganisations: List<OrganisationNameAndCode>,
    allAccessGroups: List<AccessGroup>,
) -> MemberOfToDeltaRolesMapper

class MemberOfToDeltaRolesMapper(
    private val username: String,
    allOrganisations: List<OrganisationNameAndCode>,
    allAccessGroups: List<AccessGroup>,
) {
    companion object {
        private val logger = LoggerFactory.getLogger(MemberOfToDeltaRolesMapper::class.java)
    }

    @Serializable
    data class AccessGroupRole(val name: String, val classification: String?, val organisationIds: List<String>, val isDelegate: Boolean)

    @Serializable
    data class SystemRole(@SerialName("name") val role: DeltaSystemRole, val organisationIds: List<String>)

    @Serializable
    data class ExternalRole(val name: String, val organisationIds: List<String>)

    @Serializable
    data class Roles(
        val systemRoles: List<SystemRole>,
        val externalRoles: List<ExternalRole>,
        val accessGroups: List<AccessGroupRole>,
        val organisations: List<OrganisationNameAndCode>,
    )

    private val organisationIdSuffixes =
        allOrganisations.map { "-${it.code}" }.sortedByDescending { it.length }.toList()
    private val organisationsMap = allOrganisations.associateBy { it.code }
    private val allAccessGroupsMap = allAccessGroups.associateBy { it.prefixedName }

    fun map(memberOf: List<String>): Roles {
        val roles = memberOf
            .mapNotNull(::removeDatamartDeltaPrefix)
            .mapNotNull(::parseToRoleAndOrg)

        val organisationIds = roles.filter { it.role == "user" }.mapNotNull { it.organisation?.code }.toHashSet()
        val roleOrgIdsMap = mapOf<RoleType, MutableMap<String, MutableList<String>>>(
            RoleType.SYSTEM to mutableMapOf(),
            RoleType.EXTERNAL to mutableMapOf(),
            RoleType.ACCESS_GROUP to mutableMapOf(),
            RoleType.DELEGATE to mutableMapOf(),
        )

        if (organisationIds.isEmpty()) logger.atWarn().addKeyValue("username", username).log("No organisations from AD")

        // Set the non-organisation specific roles first
        for (role in roles.filter { it.organisation == null }) {
            roleOrgIdsMap[role.type]!![role.role] = mutableListOf()
        }

        // Then go through the organisation specific ones and add the organisation ids to the role
        for (role in roles) {
            if (role.organisation == null) continue
            if (!organisationIds.contains(role.organisation.code)) {
                logger.atWarn().addKeyValue("username", username).addKeyValue("group", role.originalGroup)
                    .addKeyValue("role", role.role).addKeyValue("orgId", role.organisation.code)
                    .log("User is member of datamart-delta-<role>-<orgId> group, but not part of the organisation, i.e. not a member of datamart-delta-user-<orgId> group, discarding group")
                continue
            }

            val orgListForRole = roleOrgIdsMap[role.type]!![role.role]
            if (orgListForRole == null) {
                logger.atWarn().addKeyValue("username", username).addKeyValue("group", role.originalGroup)
                    .addKeyValue("role", role.role).addKeyValue("orgId", role.organisation.code)
                    .log("User is member of datamart-delta-<role>-<orgId> group, but not member of datamart-delta-<role> group, discarding group")
                continue
            }
            orgListForRole.add(role.organisation.code)
        }

        val delegateAccessGroups = roleOrgIdsMap[RoleType.DELEGATE]!!.entries.map { it.key.substringAfter("delegate-") }

        return Roles(
            roleOrgIdsMap[RoleType.SYSTEM]!!.entries.map {
                SystemRole(
                    DeltaSystemRole.ROLE_NAME_MAP[it.key]!!,
                    it.value
                )
            },
            roleOrgIdsMap[RoleType.EXTERNAL]!!.entries.map { ExternalRole(it.key, it.value) },
            roleOrgIdsMap[RoleType.ACCESS_GROUP]!!.entries.map {
                AccessGroupRole(
                    it.key,
                    allAccessGroupsMap[it.key]!!.classification,
                    it.value,
                    it.key in delegateAccessGroups,
                )
            },
            organisationIds.map { organisationsMap[it]!! }
        )
    }

    private enum class RoleType {
        SYSTEM,
        EXTERNAL,
        ACCESS_GROUP,
        DELEGATE,
    }

    private class ParsedRole(
        val role: String,
        val organisation: OrganisationNameAndCode?,
        val type: RoleType,
        val originalGroup: String,
    )


    private fun removeDatamartDeltaPrefix(group: String): String? {
        return if (group.startsWith(DATAMART_DELTA_PREFIX)) {
            group.substring(DATAMART_DELTA_PREFIX.length, group.length)
        } else {
            logger.atWarn().addKeyValue("username", username).addKeyValue("group", group)
                .log("Ignoring group as CN does not start with $DATAMART_DELTA_PREFIX")
            null
        }
    }

    private fun parseToRoleAndOrg(groupWithoutPrefix: String): ParsedRole? {
        /*
         * Group names take the form datamart-delta-<role name>[-<orgId>], e.g.
         * datamart-delta-data-provider-dclg
         * ______________-_____________-____
         *  ^prefix        ^role         ^organisation id
         * Where role can be a system role (like "data-provider"), or an access group (like "homelessness-research")
         * The organisation id is optional and indicates the user has that role in that organisation.
         * Role and organisation ids can both have hyphens in.
         */
        val orgId = organisationIdSuffixes.firstOrNull { groupWithoutPrefix.endsWith(it) }?.substring(1)
        val roleStr =
            if (orgId == null) groupWithoutPrefix
            else groupWithoutPrefix.substring(0, groupWithoutPrefix.length - (orgId.length + 1))

        return when (val roleType = determineRoleType(roleStr)) {
            null -> {
                logger.atWarn().addKeyValue("username", username).addKeyValue("role", roleStr)
                    .addKeyValue("orgId", orgId).addKeyValue("group", DATAMART_DELTA_PREFIX + groupWithoutPrefix)
                    .log("Ignoring group as unable to find matching system role or access group")
                null
            }

            else -> ParsedRole(roleStr, organisationsMap[orgId], roleType, DATAMART_DELTA_PREFIX + groupWithoutPrefix)
        }
    }

    private fun determineRoleType(role: String): RoleType? {
        return if (role.startsWith("delegate-") && allAccessGroupsMap.contains(role.substringAfter("delegate-"))) RoleType.DELEGATE
        else if (DeltaSystemRole.ROLE_NAME_MAP.containsKey(role)) RoleType.SYSTEM
        else if (DELTA_EXTERNAL_ROLES.contains(role)) RoleType.EXTERNAL
        else if (allAccessGroupsMap.contains(role)) RoleType.ACCESS_GROUP
        else null
    }
}

enum class DeltaSystemRoleClassification {
    EXTERNAL, // All users can choose these roles in My account on Delta
    EXTERNAL_AUDIT, // Users that are part of an auditing organisation can choose these roles in My account on Delta
    INTERNAL, // Internal (dclg) users can choose these roles in My account
    RESTRICTED, // Only admins can assign these roles
    SYSTEM;
}

@Serializable(with = DeltaSystemRoleSerializer::class)
enum class DeltaSystemRole(val adRoleName: String, val classification: DeltaSystemRoleClassification) {
    ADMIN("admin", DeltaSystemRoleClassification.SYSTEM),
    // In practice this role is used by the first line helpdesk and can perform some
    // non-read-only actions like enabling/disabling users and sending password reset emails
    READ_ONLY_ADMIN("read-only-admin", DeltaSystemRoleClassification.RESTRICTED),
    TESTERS("testers", DeltaSystemRoleClassification.INTERNAL),
    DATA_PROVIDERS("data-providers", DeltaSystemRoleClassification.EXTERNAL),
    DATA_CERTIFIERS("data-certifiers", DeltaSystemRoleClassification.EXTERNAL),
    DATA_AUDITORS("data-auditors", DeltaSystemRoleClassification.EXTERNAL_AUDIT),
    BILLING_DATA_APPROVERS("billing-data-approvers", DeltaSystemRoleClassification.RESTRICTED),
    WAREHOUSE_USERS("warehouse-users", DeltaSystemRoleClassification.RESTRICTED),
    DATASET_ADMINS("dataset-admins", DeltaSystemRoleClassification.RESTRICTED),
    FORM_DESIGNERS("form-designers", DeltaSystemRoleClassification.INTERNAL),
    LEAD_TESTERS("lead-testers", DeltaSystemRoleClassification.RESTRICTED),
    USER("user", DeltaSystemRoleClassification.SYSTEM),
    DATA_ENTRY_CLERKS("data-entry-clerks", DeltaSystemRoleClassification.RESTRICTED),
    PAYMENTS_APPROVERS("payments-approvers", DeltaSystemRoleClassification.INTERNAL),
    PAYMENTS_REVIEWERS("payments-reviewers", DeltaSystemRoleClassification.INTERNAL),
    SAP_TEAM_MEMBERS("sap-team-members", DeltaSystemRoleClassification.RESTRICTED),
    LOCAL_ADMINS("local-admins", DeltaSystemRoleClassification.RESTRICTED),
    ABATEMENTS_APPROVERS("abatements-approvers", DeltaSystemRoleClassification.RESTRICTED),
    SUSPENSIONS_APPROVERS("suspensions-approvers", DeltaSystemRoleClassification.RESTRICTED),
    WRITE_OFFS_APPROVERS("write-offs-approvers", DeltaSystemRoleClassification.RESTRICTED),
    SETUP_MANAGERS("setup-managers", DeltaSystemRoleClassification.RESTRICTED),
    REPORT_USERS("report-users", DeltaSystemRoleClassification.EXTERNAL),
    PERSONAL_DATA_OWNERS("personal-data-owners", DeltaSystemRoleClassification.RESTRICTED),
    STATS_DATA_CERTIFIERS("stats-data-certifiers", DeltaSystemRoleClassification.RESTRICTED);

    override fun toString() = adRoleName

    // The Common Name (CN) of the group representing this role in Active Directory
    fun adCn() = DATAMART_DELTA_PREFIX + adRoleName
    fun adCn(orgCode: String) = "$DATAMART_DELTA_PREFIX$adRoleName-$orgCode"

    companion object {
        val ROLE_NAME_MAP = DeltaSystemRole.entries.associateBy { it.adRoleName }
        fun fromString(str: String) = ROLE_NAME_MAP[str]
    }
}

object DeltaSystemRoleSerializer : KSerializer<DeltaSystemRole> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("DeltaSystemRole", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: DeltaSystemRole) {
        encoder.encodeString(value.adRoleName)
    }

    override fun deserialize(decoder: Decoder): DeltaSystemRole {
        val key = decoder.decodeString()
        return DeltaSystemRole.ROLE_NAME_MAP[key]
            ?: throw IllegalArgumentException("System role not found $key")
    }
}

/*
 * Name is copied from Delta, "External" in that it's managed by MarkLogic rather than Delta's Java layer.
 * We should be able to get rid of this distinction at some point, but for now Delta expects it.
 */
val DELTA_EXTERNAL_ROLES = hashSetOf("section-151-officers")

@Serializable
data class LdapUserWithRoles(val user: LdapUser, val roles: MemberOfToDeltaRolesMapper.Roles)
