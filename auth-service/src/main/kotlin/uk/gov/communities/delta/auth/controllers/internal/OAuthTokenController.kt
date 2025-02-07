package uk.gov.communities.delta.auth.controllers.internal

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.util.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import org.slf4j.LoggerFactory
import uk.gov.communities.delta.auth.config.DeltaLoginEnabledClient
import uk.gov.communities.delta.auth.repositories.LdapUser
import uk.gov.communities.delta.auth.saml.SAMLTokenService
import uk.gov.communities.delta.auth.security.ClientSecretCheck
import uk.gov.communities.delta.auth.services.*
import java.time.Instant

class OAuthTokenController(
    private val clients: List<DeltaLoginEnabledClient>,
    private val authorizationCodeService: AuthorizationCodeService,
    private val userLookupService: UserLookupService,
    private val samlTokenService: SAMLTokenService,
    private val oauthSessionService: OAuthSessionService,
    private val accessGroupsService: AccessGroupsService,
    private val organisationService: OrganisationService,
    private val memberOfToDeltaRolesMapperFactory: MemberOfToDeltaRolesMapperFactory,
    private val userAuditService: UserAuditService,
) {
    private val logger = LoggerFactory.getLogger(javaClass)

    companion object {
        const val TOKEN_EXPIRY_SECONDS = 43200L
    }

    fun route(route: Route) {
        route.post { getToken(call) }
    }

    private suspend fun getToken(call: ApplicationCall) {
        val params = call.receiveParameters()
        val code = params.getOrFail("code")
        val clientId = params.getOrFail("client_id")
        val clientSecret = params.getOrFail("client_secret")

        val client = ClientSecretCheck.getClient(clients, clientId, clientSecret)
            ?: return call.respond(
                HttpStatusCode.BadRequest,
                JsonErrorResponse("invalid_client", "Invalid client id or secret")
            )

        val userSession = exchangeAuthCodeForSession(code, client)
        if (userSession == null) {
            logger.warn("Invalid auth code '{}'", code)
            return call.respond(
                HttpStatusCode.BadRequest,
                JsonErrorResponse("invalid_grant", "Invalid auth code")
            )
        }

        coroutineScope {
            // Fetch the list of organisations and access groups while we generate the SAML token
            val allOrganisations = async { organisationService.findAllNamesAndCodes() }
            val allAccessGroups = async { accessGroupsService.getAllAccessGroups() }

            val samlToken = samlTokenService.samlTokenForSession(userSession.session, userSession.user)
            val guid = userSession.user.getGUID()
            val roles = memberOfToDeltaRolesMapperFactory(
                guid, allOrganisations.await(), allAccessGroups.await()
            ).map(userSession.user.memberOfCNs)
            val isNewUser = userAuditService.checkIsNewUser(guid)

            logger.atInfo().withSession(userSession.session).log("Successful token request")

            call.respond(
                AccessTokenResponse(
                    access_token = userSession.session.authToken,
                    delta_ldap_user = userSession.user,
                    saml_token = samlToken.token,
                    expires_at_epoch_second = samlToken.expiry.epochSecond,
                    delta_user_roles = roles,
                    is_sso = userSession.session.isSso,
                    is_new_user = isNewUser,
                )
            )
        }
    }

    private suspend fun exchangeAuthCodeForSession(code: String, client: DeltaLoginEnabledClient) =
        withContext(Dispatchers.IO) {
            val authCode = authorizationCodeService.lookupAndInvalidate(code, client) ?: return@withContext null
            val session = oauthSessionService.create(authCode, client)
            val user = userLookupService.lookupCurrentUser(session)
            UserSession(session, user)
        }

    private class UserSession(val session: OAuthSession, val user: LdapUser)

    @Suppress("PropertyName")
    @Serializable
    data class AccessTokenResponse(
        val access_token: String,
        val delta_ldap_user: LdapUser,
        val delta_user_roles: MemberOfToDeltaRolesMapper.Roles,
        val saml_token: String,
        val expires_at_epoch_second: Long,
        val token_type: String = "bearer",
        val expires_in: String = TOKEN_EXPIRY_SECONDS.toString(),
        val is_sso: Boolean,
        val is_new_user: Boolean
    )
}

data class SamlTokenWithExpiry(val token: String, val expiry: Instant)

fun SAMLTokenService.samlTokenForSession(session: OAuthSession, user: LdapUser): SamlTokenWithExpiry {
    val expiry = session.createdAt.plusSeconds(OAuthTokenController.TOKEN_EXPIRY_SECONDS)
    return SamlTokenWithExpiry(generate(session.client.samlCredential, user, session.createdAt, expiry), expiry)
}
