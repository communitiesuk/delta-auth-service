package uk.gov.communities.delta.service

import uk.gov.communities.delta.auth.services.AccessGroup
import uk.gov.communities.delta.auth.services.MemberOfToDeltaRolesMapper
import kotlin.test.Test
import kotlin.test.assertEquals

class MemberOfToDeltaRolesMapperTest {
    @Test
    fun testOrganisationMapping() {
        val result = mapper().map(
            listOf(
                "user-dclg"
            ).map { "datamart-delta-$it" }
        )

        assertEquals(emptyList(), result.systemRoles)
        assertEquals(emptyList(), result.externalRoles)
        assertEquals(emptyList(), result.accessGroups)
        assertEquals(listOf("dclg"), result.organisationIds)
    }

    @Test
    fun testIgnoresNonPrefixedGroupNames() {
        val result = mapper().map(
            listOf(
                "user-dclg"
            )
        )

        assertEquals(emptyList(), result.organisationIds)
    }

    @Test
    fun testSystemRoles() {
        val result = mapper().map(
            listOf(
                "user-dclg", "data-providers-dclg", "data-providers", "form-designers", "section-151-officers", "user"
            ).map { "datamart-delta-$it" }
        )

        assertEquals(
            listOf(
                MemberOfToDeltaRolesMapper.SystemRole("data-providers", listOf("dclg")),
                MemberOfToDeltaRolesMapper.SystemRole("form-designers", listOf()),
                MemberOfToDeltaRolesMapper.SystemRole("user", listOf("dclg")),
            ), result.systemRoles
        )
        assertEquals(
            listOf(MemberOfToDeltaRolesMapper.ExternalRole("section-151-officers", listOf())),
            result.externalRoles
        )
        assertEquals(0, result.accessGroups.size)
        assertEquals(listOf("dclg"), result.organisationIds)
    }

    @Test
    fun testIgnoresInvalidOrganisationMapping() {
        val result = mapper().map(
            listOf(
                "dclg", "data-providers-dclg", "data-providers", "user-invalid-group", "data-providers-E1234"
            ).map { "datamart-delta-$it" }
        )

        assertEquals(listOf(MemberOfToDeltaRolesMapper.SystemRole("data-providers", listOf())), result.systemRoles)
        assertEquals(emptyList(), result.externalRoles)
        assertEquals(emptyList(), result.accessGroups)
        assertEquals(emptyList(), result.organisationIds)
    }

    @Test
    fun testAccessGroupMapping() {
        val result = mapper().map(
            listOf(
                "user-dclg", "access-group", "access-group-dclg", "another-group"
            ).map { "datamart-delta-$it" }
        )

        assertEquals(emptyList(), result.systemRoles)
        assertEquals(emptyList(), result.externalRoles)
        assertEquals(
            listOf(
                MemberOfToDeltaRolesMapper.AccessGroupRole("access-group", "statistics", listOf("dclg")),
                MemberOfToDeltaRolesMapper.AccessGroupRole("another-group", null, listOf()),
            ), result.accessGroups
        )
        assertEquals(listOf("dclg"), result.organisationIds)
    }

    @Test
    fun testIgnoresInvalidAccessGroups() {
        val result = mapper().map(
            listOf(
                "user-dclg", "invalid-group", "invalid-group-dclg"
            ).map { "datamart-delta-$it" }
        )

        assertEquals(emptyList(), result.systemRoles)
        assertEquals(emptyList(), result.externalRoles)
        assertEquals(emptyList(), result.accessGroups)
        assertEquals(listOf("dclg"), result.organisationIds)
    }


    @Test
    fun testMultipleOrganisations() {
        val result = mapper().map(
            listOf(
                "user-dclg", "user-E1234", "data-providers-dclg", "data-providers-E1234", "data-certifiers-E1234",
                "data-certifiers", "data-providers", "access-group", "access-group-dclg", "access-group-E1234"
            ).map { "datamart-delta-$it" }
        )

        assertEquals(
            listOf(
                MemberOfToDeltaRolesMapper.SystemRole("data-certifiers", listOf("E1234")),
                MemberOfToDeltaRolesMapper.SystemRole("data-providers", listOf("dclg", "E1234")),
            ), result.systemRoles
        )
        assertEquals(emptyList(), result.externalRoles)
        assertEquals(
            listOf(
                MemberOfToDeltaRolesMapper.AccessGroupRole("access-group", "statistics", listOf("dclg", "E1234"))
            ), result.accessGroups
        )
        assertEquals(listOf("dclg", "E1234"), result.organisationIds)
    }

    private fun mapper() = MemberOfToDeltaRolesMapper("username", organisationIds, accessGroups)

    private val accessGroups = listOf(
        AccessGroup("access-group", "statistics", null, enableOnlineRegistration = false, enableInternalUser = false),
        AccessGroup("another-group", null, null, enableOnlineRegistration = false, enableInternalUser = false),
    )

    private val organisationIds = listOf("E1234", "dclg")
}
