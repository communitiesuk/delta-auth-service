package uk.gov.communities.delta.auth.utils

import com.google.common.base.Strings
import io.ktor.http.*
import uk.gov.communities.delta.auth.config.LDAPConfig
import uk.gov.communities.delta.auth.plugins.ApiError
import uk.gov.communities.delta.auth.plugins.UserVisibleServerError
import uk.gov.communities.delta.auth.repositories.LdapRepository
import uk.gov.communities.delta.auth.repositories.LdapUser
import uk.gov.communities.delta.auth.services.UserLookupService
import java.util.*

private fun validateGUID(userGUIDString: String) {
    if (LDAPConfig.VALID_USER_GUID_REGEX.matchEntire(userGUIDString) == null) {
        throw ApiError(HttpStatusCode.BadRequest, "invalid_guid", "Invalid user GUID $userGUIDString")
    }
}

private fun validateCN(userCN: String) {
    if (!LDAPConfig.VALID_USER_CN_REGEX.matches(userCN)) {
        throw ApiError(HttpStatusCode.BadRequest, "invalid_user_cn", "Invalid user cn $userCN")
    }
}

suspend fun getUserGUIDFromCallParameters(
    parameters: Parameters,
    userLookupService: UserLookupService,
    userVisibleErrorMessage: String,
    action: String
): UUID {
    val userCN = parameters["userCN"] ?: parameters["userCn"].orEmpty()
    val userGUIDString = parameters["userGUID"].orEmpty()
    val user: LdapUser

    // During transition from userCN to userGUID exactly one should be non-empty
    // TODO DT-1022 - simplify this to just get GUID directly
    return if (Strings.isNullOrEmpty(userGUIDString)) {
        if (Strings.isNullOrEmpty(userCN)) throw UserVisibleServerError(
            action + "_no_user_cn_or_guid",
            "User CN and GUID both not present on $action",
            userVisibleErrorMessage
        )
        validateCN(userCN)
        user = userLookupService.lookupUserByCn(userCN)
        user.getUUID()
    } else {
        if (!Strings.isNullOrEmpty(userCN)) throw UserVisibleServerError(
            action + "_both_user_cn_and_guid",
            "User CN and GUID both present on $action",
            userVisibleErrorMessage
        )
        validateGUID(userGUIDString)
        val userGUID = UUID.fromString(userGUIDString)
        userGUID
    }
}

suspend fun getUserFromCallParameters(
    parameters: Parameters,
    userLookupService: UserLookupService,
    userVisibleErrorMessage: String,
    action: String
): LdapUser {
    val userCN = parameters["userCN"] ?: parameters["userCn"].orEmpty()
    val userGUIDString = parameters["userGUID"].orEmpty()
    val userGUID: UUID

    // During transition from userCN to userGUID exactly one should be non-empty
    // TODO DT-1022 - simplify this to just look for GUID
    if (Strings.isNullOrEmpty(userGUIDString)) {
        if (Strings.isNullOrEmpty(userCN)) throw UserVisibleServerError(
            action + "_no_user_cn_or_guid",
            "User CN and GUID both not present on $action",
            userVisibleErrorMessage
        )
        validateCN(userCN)
        try {
            return userLookupService.lookupUserByCn(userCN)
        } catch (e: LdapRepository.NoUserException) {
            throw ApiError(HttpStatusCode.NotFound, "user_not_found", "User not found")
        }
    } else {
        if (!Strings.isNullOrEmpty(userCN)) throw UserVisibleServerError(
            action + "_both_user_cn_and_guid",
            "User CN and GUID both present on $action",
            userVisibleErrorMessage
        )
        validateGUID(userGUIDString)
        userGUID = UUID.fromString(userGUIDString)
        try {
            return userLookupService.lookupUserByGUID(userGUID)
        } catch (e: LdapRepository.NoUserException) {
            throw ApiError(HttpStatusCode.NotFound, "user_not_found", "User not found")
        }
    }
}
