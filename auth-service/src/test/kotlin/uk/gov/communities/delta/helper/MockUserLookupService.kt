package uk.gov.communities.delta.helper

import io.mockk.coEvery
import uk.gov.communities.delta.auth.repositories.LdapUser
import uk.gov.communities.delta.auth.services.*

fun mockUserLookupService(
    service: UserLookupService,
    users: List<Pair<LdapUser, OAuthSession?>>,
    organisations: List<OrganisationNameAndCode>,
    accessGroups: List<AccessGroup>,
) {
    for ((user, session) in users) {
        coEvery { service.lookupUserByGUID(user.getGUID()) } returns user
        coEvery { service.lookupUserByGUIDAndLoadRoles(user.getGUID()) } coAnswers {
            LdapUserWithRoles(
                user, MemberOfToDeltaRolesMapper(user.getGUID(), organisations, accessGroups).map(user.memberOfCNs)
            )
        }

        if (session != null) {
            coEvery { service.lookupCurrentUser(session) } returns user
            coEvery { service.lookupCurrentUserAndLoadRoles(session) } returns LdapUserWithRoles(
                user, MemberOfToDeltaRolesMapper(user.getGUID(), organisations, accessGroups).map(user.memberOfCNs)
            )
        }
    }
}
