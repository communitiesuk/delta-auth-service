package uk.gov.communities.delta.helper

import org.mockito.Mockito
import uk.gov.communities.delta.auth.config.OAuthClient

fun testServiceClient(clientId: String = "delta-website"): OAuthClient {
    return OAuthClient(clientId, "client-secret", Mockito.mock(), "https://delta/redirect")
}
