package uk.gov.communities.delta.auth.config

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DeltaConfigTest {
    @Test
    fun environmentWarningIsEnabledForTestAndStaging() {
        assertTrue(DeltaConfig.shouldShowEnvironmentWarning("test"))
        assertTrue(DeltaConfig.shouldShowEnvironmentWarning("staging"))
    }

    @Test
    fun environmentWarningIsDisabledForOtherEnvironmentNames() {
        assertFalse(DeltaConfig.shouldShowEnvironmentWarning(""))
        assertFalse(DeltaConfig.shouldShowEnvironmentWarning("production"))
        assertFalse(DeltaConfig.shouldShowEnvironmentWarning("development"))
        assertFalse(DeltaConfig.shouldShowEnvironmentWarning("STAGING"))
    }
}
