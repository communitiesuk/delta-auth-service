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

    suspend fun userGUIDFromEmailIfExists(userEmail: String): UUID? {
        return try {
            getGUIDFromEmail(userEmail)
        } catch (e: NoUserException) {
            null
        }
    }

    suspend fun getGUIDFromEmail(email: String): UUID {
        val cn = LDAPConfig.emailToCN(email)
        try {
            return withContext(Dispatchers.IO) {
                dbPool.useConnectionBlocking("user_guid_read") {
                    userGUIDMapRepo.getGUIDForUserCNCaseInsensitive(it, cn)
                }
            }
        } catch (e: NoUserException) {
            val user = userLookupService.lookupUserByCN(cn)
            // NB: this should not be used in production or staging but may occur on test or dev due to shared AD
            logger.atWarn().addKeyValue("lookupUserGUID", user.getGUID()).addKeyValue("lookupUserCN", cn)
                .log("Email lookup: User existed in AD but was not found in user_guid_map, will add")
            addMissingUser(user)
            return user.getGUID()
        }
    }

    suspend fun getGUIDFromCN(userCN: String): UUID {
        try {
            return withContext(Dispatchers.IO) {
                dbPool.useConnectionBlocking("user_guid_read") {
                    userGUIDMapRepo.getGUIDForUserCNCaseSensitive(it, userCN)
                }
            }
        } catch (e: NoUserException) {
            val user = userLookupService.lookupUserByCN(userCN)
            if (user.cn != userCN) {
                logger.atWarn().addKeyValue("suppliedCN", userCN).addKeyValue("actualCN", user.cn)
                    .log("Incorrect CN used when looking up user - is the casing wrong? Updating user_guid_map in case it is wrong there")
            } else {
                // NB: this should not be used in production or staging but may occur on test or dev due to shared AD
                logger.atWarn().addKeyValue("lookupUserGUID", user.getGUID()).addKeyValue("lookupUserCN", userCN)
                    .log("CN lookup: User existed in AD but was not found in user_guid_map, will add")
            }
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
