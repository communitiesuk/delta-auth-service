package uk.gov.communities.delta.helper

import io.mockk.coEvery
import io.mockk.mockk
import uk.gov.communities.delta.auth.repositories.LdapRepository
import uk.gov.communities.delta.auth.repositories.LdapUser
import uk.gov.communities.delta.auth.services.*

fun mockUserLookupService(
    service: UserLookupService,
    users: List<Pair<LdapUser, OAuthSession?>>,
    organisations: List<OrganisationNameAndCode>,
    accessGroups: List<AccessGroup>,
) {
    coEvery { service.lookupUserByCn(any()) } throws mockk<LdapRepository.NoUserException>()
    coEvery { service.lookupUserByDN(any()) } throws mockk<LdapRepository.NoUserException>()
    coEvery { service.lookupUserByCNAndLoadRoles(any()) } throws mockk<LdapRepository.NoUserException>()
    for ((user, session) in users) {
        coEvery { service.lookupUserByCn(user.cn) } returns user
        coEvery { service.lookupUserByDN(user.dn) } returns user
        coEvery {
            service.lookupUserByCNAndLoadRoles(user.cn)
        } coAnswers {
            LdapUserWithRoles(
                user,
                MemberOfToDeltaRolesMapper(user.cn, organisations, accessGroups).map(user.memberOfCNs)
            )
        }
        coEvery { service.lookupUserByEmail(user.email!!) } returns user
        coEvery { service.lookupUserByGUID(user.getGUID()) } returns user
        coEvery { service.lookupUserByGUIDAndLoadRoles(user.getGUID()) } coAnswers {
            LdapUserWithRoles(
                user, MemberOfToDeltaRolesMapper(user.cn, organisations, accessGroups).map(user.memberOfCNs)
            )
        }

        if (session != null) {
            coEvery { service.lookupCurrentUser(session) } returns user
            coEvery { service.lookupCurrentUserAndLoadRoles(session) } returns LdapUserWithRoles(
                user, MemberOfToDeltaRolesMapper(user.cn, organisations, accessGroups).map(user.memberOfCNs)
            )
        }
    }
}
