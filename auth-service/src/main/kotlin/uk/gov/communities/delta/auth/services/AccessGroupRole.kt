package uk.gov.communities.delta.auth.services

import kotlinx.serialization.Serializable

@Serializable
data class AccessGroupRole(
    val name: String,
    val displayName: String?,
    val classification: String?,
    val organisationIds: List<String>,
    val isDelegate: Boolean,
)
