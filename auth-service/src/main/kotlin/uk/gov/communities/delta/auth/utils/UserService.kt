package uk.gov.communities.delta.auth.utils

import java.util.*

class UserService {
//    TODO - implement any needed functions
//              - findUserById
//              - createUser
//              - any they (^) use

    //    private val logger = LoggerFactory.getLogger(javaClass)
//
//    fun findUserById(id: String): Optional<User> {
//        return findUserById(id, false)
//    }
//
    fun findUserById(id: String?, includeNonDeltaUsers: Boolean): Optional<User> {
//        return userDirectoryService.findUserByEmailAddress(id, includeNonDeltaUsers).map(adUserToUser)
        return Optional.empty()
//      TODO - make this return what it should
    }
//
//    val users: List<User>
//        get() = getUsersByAuthorityId("datamart-delta-user")
//
//    fun getUsersByAuthorityId(authorityId: String?): List<User> {
//        return userDirectoryService.findUsersByRole(authorityId)
//            .stream()
//            .map(adUserToUser)
//            .collect(Collectors.toList())
//    }
//
//    fun createUser(user: User) {
//        createUserInAD(user)
//        organisationUserService.addUserToDelta(user)
//        doUpdateOrganisations(user)
//        userAuthoritiesService.doUpdateAuthorities(user)
//        startActivationProcess(user)
//    }
//
//    fun attachUser(user: User) {
//        saveUserInAD(user)
//        organisationUserService.addUserToDelta(user)
//        doUpdateOrganisations(user)
//        userAuthoritiesService.doUpdateAuthorities(user)
//        attachAccountEmailService.sendAttachAccountEmail(user::getEmail)
//    }
//
//    fun updateUser(user: User) {
//        saveUserInAD(user)
//        doUpdateOrganisations(user)
//        userAuthoritiesService.doUpdateAuthorities(user)
//    }
//
//    private fun startActivationProcess(user: User) {
//        val request: ForgotPasswordRequest = object : ForgotPasswordRequest() {
//            val userId: String
//                get() = user.getEmail()
//        }
//        val result: ForgotPasswordResult = passwordService.forgotPassword(request)
//        if (result.isSuccessful()) sendActivationEmail(request, result)
//    }
//
//    private fun sendActivationEmail(command: ForgotPasswordRequest, result: ForgotPasswordResult) {
//        val request: ActivateAccountEmailService.Request = object : Request() {
//            val emailAddress: String
//                get() = command.getUserId()
//            val token: String
//                get() = result.getToken()
//        }
//        activateAccountEmailService.sendActivationEmail(request)
//    }
//
//    private fun createUserInAD(user: User) {
//        val userId: String = emailToUID.apply(user.getEmail())
//        val adUser = ADUser()
//        adUser.setUid(userId)
//        adUser.setId(idToRDN.andThen(dnToLdapName).apply(userId))
//        fillInAdUser(user, adUser)
//        val userDN: String = idToDN.apply(userId)
//        adUser.setDn(userDN)
//        adUser.setUserPrincipalName(emailToADPrincipalName.apply(userId))
//        adUser.setStatus("active")
//        userStorageService.create(adUser)
//    }
//
//    private fun saveUserInAD(user: User) {
//        val adUser: ADUser =
//            userDirectoryService.findUserByEmailAddress(user.getId(), true).orElseThrow { UserNotFoundException() }
//        fillInAdUser(user, adUser)
//        userStorageService.save(adUser)
//    }
//
//    private fun doUpdateOrganisations(user: User) {
//        val current = getCurrentOrgIds(user)
//        val updating: List<String> = user.getOrganisationIds()
//        val adding = updating.stream()
//            .filter { a: String -> !current.contains(a) }
//            .collect(Collectors.toList())
//        val removing = current.stream()
//            .filter { a: String -> !updating.contains(a) }
//            .collect(Collectors.toList())
//        organisationUserService.addUserToOrganisations(user, adding)
//        organisationUserService.removeUserFromOrganisations(user, removing)
//    }
//
//    private fun getCurrentOrgIds(user: User): List<String> {
//        val adminCapability: UserCapability =
//            userCapabilityService.findCurrentUserCapability().orElseThrow { RuntimeException() }
//        val orgFilter: Predicate<String>
//        orgFilter = if (adminCapability.isDeltaAdmin() || adminCapability.isDatasetAdmin()) {
//            Predicate { s: String? -> true }
//        } else if (adminCapability.isLocalAdmin()) {
//            Predicate { s: String? ->
//                adminCapability.getOrganisationIds().contains(s)
//            }
//        } else {
//            Predicate { s: String? -> false }
//        }
//        return findUserById(user.getId())
//            .map<Any>(User::getOrganisationIds)
//            .orElseGet { emptyList() }
//            .stream()
//            .filter(orgFilter)
//            .collect(Collectors.toList())
//    }
//
//    private fun fillInAdUser(user: User, adUser: ADUser) {
//        adUser.setFirstName(Strings.emptyToNull(user.getFirstName()))
//        adUser.setLastName(Strings.emptyToNull(user.getLastName()))
//        adUser.setEmail(Strings.emptyToNull(user.getEmail()))
//        adUser.setPhone(Strings.emptyToNull(user.getTelephone()))
//        adUser.setMobile(Strings.emptyToNull(user.getMobile()))
//        adUser.setPosition(Strings.emptyToNull(user.getPosition()))
//        adUser.setReasonForAccess(Strings.emptyToNull(user.getReasonForAccess()))
//        adUser.setComment(Strings.emptyToNull(user.getComment()))
//        var userAccountControlFlags = 0
//        userAccountControlFlags = if (user.isEnabled()) {
//            userAccountControlFlags and uk.gov.communities.delta.system.users.common.services.UserService.Default.Companion.ACCOUNT_DISABLE_FLAG.inv()
//        } else {
//            userAccountControlFlags or uk.gov.communities.delta.system.users.common.services.UserService.Default.Companion.ACCOUNT_DISABLE_FLAG
//        }
//        adUser.setUserAccountControl(Integer.toString(userAccountControlFlags))
//    }
//
//    fun updateUsername(oldEmailAddress: String?, newEmailAddress: String?) {
//        userNameService.update(oldEmailAddress, newEmailAddress)
//    }
//
//    companion object {
//        private val ACCOUNT_DISABLE_FLAG: Int = UserAccountControlFlags.ACCOUNTDISABLE.getFlag()
//    }
}