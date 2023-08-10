package uk.gov.communities.delta.helper

import io.mockk.mockk
import uk.gov.communities.delta.auth.config.OAuthClient

fun testServiceClient(clientId: String = "delta-website"): OAuthClient {
    return OAuthClient(clientId, "client-secret", mockk(), "https://delta")
}
