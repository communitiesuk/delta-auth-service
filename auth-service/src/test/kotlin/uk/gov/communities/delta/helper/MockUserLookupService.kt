package uk.gov.communities.delta.helper

import io.mockk.coEvery
import uk.gov.communities.delta.auth.repositories.LdapUser
import uk.gov.communities.delta.auth.services.AccessGroup
import uk.gov.communities.delta.auth.services.MemberOfToDeltaRolesMapper
import uk.gov.communities.delta.auth.services.OrganisationNameAndCode
import uk.gov.communities.delta.auth.services.UserLookupService
import javax.naming.NameNotFoundException

fun mockUserLookupService(
    service: UserLookupService,
    users: List<LdapUser>,
    organisations: List<OrganisationNameAndCode>,
    accessGroups: List<AccessGroup>,
) {
    coEvery { service.lookupUserByCn(any()) } throws NameNotFoundException()
    coEvery { service.lookupUserByDN(any()) } throws NameNotFoundException()
    coEvery { service.lookupUserByCNAndLoadRoles(any()) } throws NameNotFoundException()
    for (user in users) {
        coEvery { service.lookupUserByCn(user.cn) } returns user
        coEvery { service.lookupUserByDN(user.dn) } returns user
        coEvery {
            service.lookupUserByCNAndLoadRoles(
                user.cn
            )
        } coAnswers {
            UserLookupService.UserWithRoles(
                user,
                MemberOfToDeltaRolesMapper(
                    user.cn, organisations, accessGroups
                ).map(user.memberOfCNs)
            )
        }
    }
}
