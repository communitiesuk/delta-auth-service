package uk.gov.communities.delta.auth.services

import kotlinx.serialization.Serializable
import org.slf4j.LoggerFactory

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
        const val DATAMART_DELTA_PREFIX = "datamart-delta-"
        private val logger = LoggerFactory.getLogger(MemberOfToDeltaRolesMapper::class.java)
    }

    @Serializable
    data class AccessGroupRole(val name: String, val classification: String?, val organisationIds: List<String>)

    @Serializable
    data class SystemRole(val name: String, val organisationIds: List<String>)

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
    private val allAccessGroupsMap = allAccessGroups.associateBy { it.name }

    fun map(memberOf: List<String>): Roles {
        val roles = memberOf
            .mapNotNull(::removeDatamartDeltaPrefix)
            .mapNotNull(::parseToRoleAndOrg)

        val organisationIds = roles.filter { it.role == "user" }.mapNotNull { it.organisation?.code }.toHashSet()
        val roleOrgIdsMap = mapOf<RoleType, MutableMap<String, MutableList<String>>>(
            RoleType.SYSTEM to mutableMapOf(),
            RoleType.EXTERNAL to mutableMapOf(),
            RoleType.ACCESS_GROUP to mutableMapOf(),
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

        return Roles(
            roleOrgIdsMap[RoleType.SYSTEM]!!.entries.map { SystemRole(it.key, it.value) },
            roleOrgIdsMap[RoleType.EXTERNAL]!!.entries.map { ExternalRole(it.key, it.value) },
            roleOrgIdsMap[RoleType.ACCESS_GROUP]!!.entries.map {
                AccessGroupRole(
                    it.key,
                    allAccessGroupsMap[it.key]!!.classification,
                    it.value
                )
            },
            organisationIds.map { organisationsMap[it]!! }
        )
    }

    private enum class RoleType {
        SYSTEM,
        EXTERNAL,
        ACCESS_GROUP,
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

        val roleType = determineRoleType(roleStr)
        return if (roleType == null) {
            logger.atWarn().addKeyValue("username", username).addKeyValue("role", roleStr)
                .addKeyValue("orgId", orgId).addKeyValue("group", DATAMART_DELTA_PREFIX + groupWithoutPrefix)
                .log("Ignoring group as unable to find matching system role or access group")
            null
        } else {
            ParsedRole(roleStr, organisationsMap[orgId], roleType, DATAMART_DELTA_PREFIX + groupWithoutPrefix)
        }
    }

    private fun determineRoleType(role: String): RoleType? {
        return if (DELTA_SYSTEM_ROLES.contains(role)) RoleType.SYSTEM
        else if (DELTA_EXTERNAL_ROLES.contains(role)) RoleType.EXTERNAL
        else if (allAccessGroupsMap.contains(role)) RoleType.ACCESS_GROUP
        else null
    }
}

val DELTA_SYSTEM_ROLES = hashSetOf(
    "admin",
    "read-only-admin",
    "testers",
    "data-providers",
    "data-certifiers",
    "data-auditors",
    "billing-data-approvers",
    "warehouse-users",
    "dataset-admins",
    "form-designers",
    "lead-testers",
    "user",
    "data-entry-clerks",
    "payments-approvers",
    "payments-reviewers",
    "sap-team-members",
    "local-admins",
    "abatements-approvers",
    "suspensions-approvers",
    "write-offs-approvers",
    "setup-managers",
    "report-users",
    "personal-data-owners",
    "stats-data-certifiers",
)

/*
 * Name is copied from Delta, "External" in that it's managed by MarkLogic rather than Delta's Java layer.
 * We should be able to get rid of this distinction at some point, but for now Delta expects it.
 */
val DELTA_EXTERNAL_ROLES = hashSetOf("section-151-officers")
