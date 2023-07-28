package uk.gov.communities.delta.auth.controllers.internal

import kotlinx.serialization.Serializable

@Serializable
data class JsonErrorResponse(val error: String, val errorDescription: String? = null)
