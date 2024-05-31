package uk.gov.communities.delta.auth.services

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.LDAPConfig
import uk.gov.communities.delta.auth.plugins.NoUserException
import uk.gov.communities.delta.auth.repositories.DbPool
import uk.gov.communities.delta.auth.repositories.LdapUser
import uk.gov.communities.delta.auth.repositories.UserGUIDMapRepo
import java.util.*

class UserGUIDMapService(
    private val userGUIDMapRepo: UserGUIDMapRepo,
    private val userLookupService: UserLookupService,
    private val dbPool: DbPool
) {
    private val logger = LoggerFactory.getLogger(javaClass)

    suspend fun userGUIDIfExists(userEmail: String): UUID? {
        return try {
            getGUIDFromEmail(userEmail)
        } catch (e: NoUserException) {
            null
        }
    }

    suspend fun getGUIDFromEmail(email: String): UUID {
        return getGUID(LDAPConfig.emailToCN(email))
    }

    suspend fun getGUID(userCN: String): UUID {
        try {
            return withContext(Dispatchers.IO) {
                dbPool.useConnectionBlocking("user_guid_read") {
                    userGUIDMapRepo.getGUIDForUser(it, userCN)
                }
            }
        } catch (e: NoUserException) {
            val user = userLookupService.lookupUserByCN(userCN)
            // NB: this should not be used in production or staging but may occur on test or dev due to shared AD
            logger.atWarn().log("User with GUID {} existed in AD but was not found in user_guid_map", user.getGUID())
            addMissingUser(user)
            return user.getGUID()
        }
    }

    suspend fun updateUserCN(
        user: LdapUser,
        newUserCN: String,
    ) {
        withContext(Dispatchers.IO) {
            dbPool.useConnectionBlocking("updating_user_cn") {
                userGUIDMapRepo.updateUser(it, user, newUserCN)
                it.commit()
            }
        }
    }

    suspend fun addNewUser(user: LdapUser) {
        withContext(Dispatchers.IO) {
            dbPool.useConnectionBlocking("updating_user_cn") {
                userGUIDMapRepo.newUser(it, user)
                it.commit()
            }
        }
    }

    private suspend fun addMissingUser(user: LdapUser) {
        withContext(Dispatchers.IO) {
            dbPool.useConnectionBlocking("add_missing_user") {
                userGUIDMapRepo.addMissingUser(it, user)
                it.commit()
            }
        }
    }
}
