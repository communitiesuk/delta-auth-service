package uk.gov.communities.delta.dbintegration

import io.ktor.server.application.*
import io.ktor.test.dispatcher.*
import io.mockk.*
import kotlinx.coroutines.runBlocking
import org.junit.Assert
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test
import uk.gov.communities.delta.auth.plugins.NoUserException
import uk.gov.communities.delta.auth.repositories.UserGUIDMapRepo
import uk.gov.communities.delta.auth.services.UserGUIDMapService
import uk.gov.communities.delta.auth.services.UserLookupService
import uk.gov.communities.delta.helper.testLdapUser
import uk.gov.communities.delta.helper.testServiceClient
import kotlin.test.assertEquals

class UserGUIDMapTest {

    @Test
    fun testGetGUID() = testSuspend {
        val user = testLdapUser(email = "getGUID@test.com", cn = "getGUID!test.com")
        coEvery { userLookupService.lookupUserByCN(user.cn) } throws NoUserException("Test exception")
        assertEquals(null, service.userGUIDIfExists(user.email!!))
        coVerify(exactly = 1) { userLookupService.lookupUserByCN(user.cn) }
        service.addNewUser(user)
        assertEquals(user.getGUID(), service.userGUIDIfExists(user.email!!))
        confirmVerified(userLookupService)
    }

    @Test
    fun testThrowsErrorIfNoUser() = testSuspend {
        val user = testLdapUser(email = "throwError@test.com", cn = "throwError!test.com")
        Assert.assertThrows(NoUserException::class.java) {
            runBlocking {
                coEvery { userLookupService.lookupUserByCN(user.cn) } throws NoUserException("Test exception")
                service.getGUID(user.cn)
            }
        }.apply {
            coVerify(exactly = 1) { userLookupService.lookupUserByCN(user.cn) }
        }
    }

    @Test
    fun testAddRowIfInADButNotInTable() = testSuspend {
        val user = testLdapUser(email = "addRow@test.com", cn = "addRow!test.com")
        coEvery { userLookupService.lookupUserByCN(user.cn) } returns user
        assertEquals(user.getGUID(), service.userGUIDIfExists(user.email!!))
        coVerify(exactly = 1) { userLookupService.lookupUserByCN(user.cn) }
        assertEquals(user.getGUID(), service.userGUIDIfExists(user.email!!))
        confirmVerified(userLookupService)
    }

    @Test
    fun testUpdateUserCN() = testSuspend {
        val user = testLdapUser(email = "toUpdate@test.com", cn = "toUpdate!test.com")
        service.addNewUser(user)
        assertEquals(user.getGUID(), service.userGUIDIfExists(user.email!!))
        service.updateUserCN(user, "updatedUser!test.com")
        assertEquals(user.getGUID(), service.getGUIDFromEmail("updatedUser@test.com"))
        assertEquals(user.getGUID(), service.getGUID("updatedUser!test.com"))
    }

    @Test
    fun testUpdateNotExistingUserCN() = testSuspend {
        val user = testLdapUser(email = "toUpdateNotExisting@test.com", cn = "toUpdateNotExisting!test.com")
        service.updateUserCN(user, "updatedNotExistingUser!test.com")
        assertEquals(user.getGUID(), service.getGUIDFromEmail("updatedNotExistingUser@test.com"))
        assertEquals(user.getGUID(), service.getGUID("updatedNotExistingUser!test.com"))
    }

    @Before
    fun resetMocks() {
        clearAllMocks()
    }

    companion object {
        lateinit var service: UserGUIDMapService
        val userLookupService = mockk<UserLookupService>()
        val client = testServiceClient()
        val call = mockk<ApplicationCall>()

        @BeforeClass
        @JvmStatic
        fun setup() {
            val repo = UserGUIDMapRepo()
            service = UserGUIDMapService(repo, userLookupService, testDbPool)
        }
    }

}
