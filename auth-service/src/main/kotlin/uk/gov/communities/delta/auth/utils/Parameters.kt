package uk.gov.communities.delta.auth.utils

import com.google.common.base.Strings
import io.ktor.http.*
import uk.gov.communities.delta.auth.config.LDAPConfig
import uk.gov.communities.delta.auth.plugins.ApiError
import uk.gov.communities.delta.auth.plugins.NoUserException
import uk.gov.communities.delta.auth.plugins.UserVisibleServerError
import uk.gov.communities.delta.auth.repositories.LdapUser
import uk.gov.communities.delta.auth.services.UserGUIDMapService
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

fun getIdentifyingParameterOrEmpty(parameters: Parameters) :String {
    return parameters["userCN"] ?: parameters["userCn"] ?: parameters["cn"] ?: parameters["userGUID"].orEmpty()
}

suspend fun getUserGUIDFromCallParameters(
    parameters: Parameters,
    userGUIDMapService: UserGUIDMapService,
    userVisibleErrorMessage: String,
    action: String
): UUID {
    val userCN = parameters["userCN"] ?: parameters["userCn"] ?: parameters["cn"].orEmpty()
    val userGUIDString = parameters["userGUID"].orEmpty()

    // During transition from userCN to userGUID exactly one should be non-empty
    // TODO DT-1022 - simplify this to just get GUID from call once receiving GUID in all places
    //  NB: Password flow used to send userCN and some people may still have (expired) links using that
    return if (Strings.isNullOrEmpty(userGUIDString)) {
        if (Strings.isNullOrEmpty(userCN)) throw UserVisibleServerError(
            action + "_no_user_cn_or_guid",
            "User CN and GUID both not present on $action",
            userVisibleErrorMessage
        )
        validateCN(userCN)
        userGUIDMapService.getGUID(userCN)
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
    userGUIDMapService: UserGUIDMapService,
    userVisibleErrorMessage: String,
    action: String
): LdapUser {
    val userGUID = getUserGUIDFromCallParameters(parameters, userGUIDMapService, userVisibleErrorMessage, action)

    try {
        return userLookupService.lookupUserByGUID(userGUID)
    } catch (e: NoUserException) {
        throw ApiError(HttpStatusCode.BadRequest, "user_not_found", "User not found")
    }
}
