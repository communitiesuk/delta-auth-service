package uk.gov.communities.delta.helper

import io.mockk.mockk
import uk.gov.communities.delta.auth.config.DeltaLoginEnabledClient

fun testServiceClient(clientId: String = "delta-website"): DeltaLoginEnabledClient {
    return DeltaLoginEnabledClient(clientId, "client-secret", mockk(), "https://delta")
}
