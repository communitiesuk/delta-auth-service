package uk.gov.communities.delta.service

import io.ktor.test.dispatcher.*
import io.mockk.*
import org.junit.BeforeClass
import uk.gov.communities.delta.auth.repositories.LdapRepository
import uk.gov.communities.delta.auth.repositories.LdapUser
import uk.gov.communities.delta.auth.services.*
import uk.gov.communities.delta.helper.testLdapUser
import javax.naming.ldap.InitialLdapContext
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class UserLookupServiceTest {

    @Test
    fun testLookupUser() = testSuspend {
        val testUser = testLdapUser()
        every { ldapRepository.mapUserFromContext(any(), "CN=some!user") } returns testUser
        val result = userLookupService.lookupUserByCn("some!user")
        assertTrue { testUser === result }
    }

    @Test
    fun testMapUser() = testSuspend {
        val testUser = testLdapUser(memberOfCNs = listOf("datamart-delta-user", "datamart-delta-user-orgCode1", "datamart-delta-access-group-1"))
        every { ldapRepository.mapUserFromContext(any(), "CN=some!user") } returns testUser

        val result = userLookupService.lookupUserByCNAndLoadRoles("some!user")
        assertTrue { testUser === result.user }
        assertEquals(DeltaSystemRole.USER, result.roles.systemRoles.single().role)
        assertEquals("orgCode1", result.roles.organisations.single().code)
        assertEquals("access-group-1", result.roles.accessGroups.single().name)
    }

    @BeforeTest
    fun resetMocks() {
        clearAllMocks()
        val block = slot<(InitialLdapContext) -> LdapUser>()
        coEvery { ldapServiceUserBind.useServiceUserBind(capture(block)) } coAnswers { block.invoke(mockk<InitialLdapContext>()) }

        coEvery { organisationService.findAllNamesAndCodes() } returns listOf(
            OrganisationNameAndCode("orgCode1", "Organisation Name 1"),
        )
        coEvery { accessGroupsService.getAllAccessGroups() } returns listOf(
            AccessGroup("access-group-1", null, null, true, true),
        )
    }

    companion object {
        private lateinit var organisationService: OrganisationService
        private lateinit var accessGroupsService: AccessGroupsService
        private lateinit var ldapRepository: LdapRepository
        private lateinit var ldapServiceUserBind: LdapServiceUserBind
        private lateinit var userLookupService: UserLookupService

        @BeforeClass
        @JvmStatic
        fun setup() {
            organisationService = mockk<OrganisationService>()
            accessGroupsService = mockk<AccessGroupsService>()
            ldapRepository = mockk<LdapRepository>()
            ldapServiceUserBind = mockk<LdapServiceUserBind>()
            userLookupService = UserLookupService(
                "CN=%s",
                ldapServiceUserBind,
                ldapRepository,
                organisationService,
                accessGroupsService,
                ::MemberOfToDeltaRolesMapper
            )
        }
    }
}
