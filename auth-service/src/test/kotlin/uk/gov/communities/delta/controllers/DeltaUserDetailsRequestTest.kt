package uk.gov.communities.delta.controllers

import uk.gov.communities.delta.auth.controllers.internal.DeltaUserDetailsRequest
import uk.gov.communities.delta.auth.controllers.internal.DeltaUserPermissions
import uk.gov.communities.delta.auth.services.AccessGroup
import uk.gov.communities.delta.auth.services.AccessGroupRole
import uk.gov.communities.delta.auth.services.DeltaSystemRole
import uk.gov.communities.delta.auth.services.OrganisationNameAndCode
import kotlin.test.Test
import kotlin.test.assertEquals

class DeltaUserDetailsRequestTest {
    @Test
    fun testGetGroupsFromUserDetails() {
        val permissions = DeltaUserPermissions(
            setOf(OrganisationNameAndCode("orgCode1", "Org 1"), OrganisationNameAndCode("orgCode2", "Org 2")),
            setOf(DeltaSystemRole.USER, DeltaSystemRole.DATA_PROVIDERS),
            setOf(
                AccessGroupRole("access-group-1", null, null, emptyList(), false),
                AccessGroupRole("access-group-2", null, null, listOf("orgCode1", "orgCode2"), true),
            )
        )
        val groups = permissions.getADGroupCNs()
        val expectedGroups = listOf(
            "datamart-delta-user",
            "datamart-delta-access-group-1",
            "datamart-delta-access-group-2",
            "datamart-delta-delegate-access-group-2",
            "datamart-delta-access-group-2-orgCode1",
            "datamart-delta-access-group-2-orgCode2",
            "datamart-delta-data-providers",
            "datamart-delta-data-providers-orgCode1",
            "datamart-delta-data-providers-orgCode2",
            "datamart-delta-user-orgCode1",
            "datamart-delta-user-orgCode2",
        )
        assertEquals(expectedGroups.sorted(), groups.sorted())
    }

    private val exampleRequest = DeltaUserDetailsRequest(
        "user@example.com",
        false,
        "user@example.com",
        "testLast",
        "testFirst",
        "0123456789",
        "0987654321",
        "test position",
        null,
        listOf("datamart-delta-access-group-1", "datamart-delta-access-group-2"),
        listOf("datamart-delta-access-group-2"),
        mapOf("datamart-delta-access-group-2" to listOf("orgCode1", "orgCode2")),
        listOf("datamart-delta-data-providers"),
        emptyList(),
        listOf("orgCode1", "orgCode2"),
        "test comment",
        null
    )

    private val organisations = listOf(
        OrganisationNameAndCode("orgCode1", "Org 1"),
        OrganisationNameAndCode("orgCode2", "Org 2"),
        OrganisationNameAndCode("orgCode3", "Org 3"),
    )

    @Suppress("BooleanLiteralArgument")
    private val accessGroups = listOf(
        AccessGroup("access-group-1", "STATS", "access group 1", false, false),
        AccessGroup("access-group-2", "STATS", "access group 2", false, false),
        AccessGroup("access-group-3", "STATS", "access group 3", false, false),
    )

    @Test
    fun testMapsRequestToPermissions() {
        val result = DeltaUserPermissions.fromUserDetailsRequest(
            exampleRequest,
            accessGroups.associateBy { it.prefixedName },
            organisations.associateBy { it.code }
        )

        assertEquals(
            DeltaUserPermissions(
                setOf(OrganisationNameAndCode("orgCode1", "Org 1"), OrganisationNameAndCode("orgCode2", "Org 2")),
                setOf(DeltaSystemRole.DATA_PROVIDERS, DeltaSystemRole.USER),
                setOf(
                    AccessGroupRole("access-group-1", "access group 1", "STATS", emptyList(), false),
                    AccessGroupRole("access-group-2", "access group 2", "STATS", listOf("orgCode1", "orgCode2"), true)
                )
            ),
            result
        )
    }

    @Test(expected = DeltaUserPermissions.Companion.BadInput::class)
    fun testRejectsInvalidAccessGroup() {
        DeltaUserPermissions.fromUserDetailsRequest(
            exampleRequest.copy(accessGroups = exampleRequest.accessGroups + "datamart-delta-invalid-group"),
            accessGroups.associateBy { it.prefixedName },
            organisations.associateBy { it.code }
        )
    }

    @Test(expected = DeltaUserPermissions.Companion.BadInput::class)
    fun testRejectsInvalidSystemRole() {
        DeltaUserPermissions.fromUserDetailsRequest(
            exampleRequest.copy(roles = listOf("datamart-delta-invalid-role")),
            accessGroups.associateBy { it.prefixedName },
            organisations.associateBy { it.code }
        )
    }

    @Test(expected = DeltaUserPermissions.Companion.BadInput::class)
    fun testRejectsInvalidOrganisation() {
        DeltaUserPermissions.fromUserDetailsRequest(
            exampleRequest.copy(organisations = exampleRequest.organisations + "invalidOrg"),
            accessGroups.associateBy { it.prefixedName },
            organisations.associateBy { it.code }
        )
    }

    @Test(expected = DeltaUserPermissions.Companion.BadInput::class)
    fun testRejectsAccessGroupInMapNotList() {
        DeltaUserPermissions.fromUserDetailsRequest(
            exampleRequest.copy(accessGroupOrganisations = mapOf("datamart-delta-access-group-3" to emptyList())),
            accessGroups.associateBy { it.prefixedName },
            organisations.associateBy { it.code }
        )
    }

    @Test(expected = DeltaUserPermissions.Companion.BadInput::class)
    fun testRejectsOrganisationInAccessGroupMapNotMember() {
        DeltaUserPermissions.fromUserDetailsRequest(
            exampleRequest.copy(accessGroupOrganisations = mapOf("datamart-delta-access-group-2" to listOf("orgCode3"))),
            accessGroups.associateBy { it.prefixedName },
            organisations.associateBy { it.code }
        )
    }

    @Test(expected = DeltaUserPermissions.Companion.BadInput::class)
    fun testRejectsDelegateNotMemberOfAccessGroup() {
        DeltaUserPermissions.fromUserDetailsRequest(
            exampleRequest.copy(accessGroupDelegates = listOf("datamart-delta-access-group-3")),
            accessGroups.associateBy { it.prefixedName },
            organisations.associateBy { it.code }
        )
    }
}
