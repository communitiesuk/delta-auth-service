package uk.gov.communities.delta.service

import uk.gov.communities.delta.auth.services.AccessGroup
import uk.gov.communities.delta.auth.services.DeltaSystemRole
import uk.gov.communities.delta.auth.services.MemberOfToDeltaRolesMapper
import uk.gov.communities.delta.auth.services.OrganisationNameAndCode
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
        assertEquals(listOf(OrganisationNameAndCode("dclg", "The Department")), result.organisations)
    }

    @Test
    fun testIgnoresNonPrefixedGroupNames() {
        val result = mapper().map(
            listOf(
                "user-dclg"
            )
        )

        assertEquals(emptyList(), result.organisations)
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
                MemberOfToDeltaRolesMapper.SystemRole(DeltaSystemRole.DATA_PROVIDERS, listOf("dclg")),
                MemberOfToDeltaRolesMapper.SystemRole(DeltaSystemRole.FORM_DESIGNERS, listOf()),
                MemberOfToDeltaRolesMapper.SystemRole(DeltaSystemRole.USER, listOf("dclg")),
            ), result.systemRoles
        )
        assertEquals(
            listOf(MemberOfToDeltaRolesMapper.ExternalRole("section-151-officers", listOf())),
            result.externalRoles
        )
        assertEquals(0, result.accessGroups.size)
        assertEquals(listOf("dclg"), result.organisations.map { it.code })
    }

    @Test
    fun testIgnoresInvalidOrganisationMapping() {
        val result = mapper().map(
            listOf(
                "dclg", "data-providers-dclg", "data-providers", "user-invalid-group", "data-providers-E1234"
            ).map { "datamart-delta-$it" }
        )

        assertEquals(listOf(MemberOfToDeltaRolesMapper.SystemRole(DeltaSystemRole.DATA_PROVIDERS, listOf())), result.systemRoles)
        assertEquals(emptyList(), result.externalRoles)
        assertEquals(emptyList(), result.accessGroups)
        assertEquals(emptyList(), result.organisations)
    }

    @Test
    fun testAccessGroupMapping() {
        val result = mapper().map(
            listOf(
                "user-dclg",
                "access-group",
                "access-group-dclg",
                "another-group",
                "yet-another-group",
                "delegate-yet-another-group",
            ).map { "datamart-delta-$it" }
        )

        assertEquals(emptyList(), result.systemRoles)
        assertEquals(emptyList(), result.externalRoles)
        assertEquals(
            listOf(
                MemberOfToDeltaRolesMapper.AccessGroupRole("access-group", "statistics", listOf("dclg"), false),
                MemberOfToDeltaRolesMapper.AccessGroupRole("another-group", null, listOf(), false),
                MemberOfToDeltaRolesMapper.AccessGroupRole("yet-another-group", null, listOf(), true),
            ), result.accessGroups
        )
        assertEquals(listOf("dclg"), result.organisations.map { it.code })
    }

    @Test
    fun testIgnoresInvalidAccessGroups() {
        val result = mapper().map(
            listOf(
                "user-dclg", "invalid-group", "invalid-group-dclg", "delegate-invalid-access-group"
            ).map { "datamart-delta-$it" }
        )

        assertEquals(emptyList(), result.systemRoles)
        assertEquals(emptyList(), result.externalRoles)
        assertEquals(emptyList(), result.accessGroups)
        assertEquals(listOf("dclg"), result.organisations.map { it.code })
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
                MemberOfToDeltaRolesMapper.SystemRole(DeltaSystemRole.DATA_CERTIFIERS, listOf("E1234")),
                MemberOfToDeltaRolesMapper.SystemRole(DeltaSystemRole.DATA_PROVIDERS, listOf("dclg", "E1234")),
            ), result.systemRoles
        )
        assertEquals(emptyList(), result.externalRoles)
        assertEquals(
            listOf(
                MemberOfToDeltaRolesMapper.AccessGroupRole("access-group", "statistics", listOf("dclg", "E1234"), false)
            ), result.accessGroups
        )
        assertEquals(listOf("dclg", "E1234"), result.organisations.map { it.code })
    }

    private fun mapper() = MemberOfToDeltaRolesMapper("username", organisations, accessGroups)

    private val accessGroups = listOf(
        AccessGroup("access-group", "statistics", null, enableOnlineRegistration = false, enableInternalUser = false),
        AccessGroup("another-group", null, null, enableOnlineRegistration = false, enableInternalUser = false),
        AccessGroup("yet-another-group", null, null, enableOnlineRegistration = false, enableInternalUser = false)
    )

    private val organisations = listOf(OrganisationNameAndCode("E1234", "Test org 1"), OrganisationNameAndCode("dclg", "The Department"))
}
