package uk.gov.communities.delta.auth.services

class UserLookupService(
    private val config: Configuration,
    private val ldapService: LdapService,
) {
    data class Configuration(
        val userDnFormat: String,
        val bindUserDn: String,
        val bindUserPassword: String,
    )

    fun lookupUserByCn(cn: String): LdapUser {
        val dn = config.userDnFormat.format(cn)
        val ctx = ldapService.bind(config.bindUserDn, config.bindUserPassword, poolConnection = true)
        try {
            return ldapService.mapUserFromContext(ctx, dn)
        } finally {
            ctx.close()
        }
    }
}
