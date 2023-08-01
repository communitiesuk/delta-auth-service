package uk.gov.communities.delta.auth.config

class Env {
    companion object {
        val devFallbackEnabled = getEnv("DISABLE_DEVELOPMENT_FALLBACK") != "true"

        fun getEnv(name: String): String? = System.getenv(name)

        fun getEnvOrDevFallback(name: String, devFallback: String) = getEnvOrDevFallback(name) { devFallback }

        fun getEnvOrDevFallback(name: String, fallback: () -> String): String {
            val env = getEnv(name)
            if (!env.isNullOrEmpty()) return env
            return if (devFallbackEnabled) fallback() else throw MissingRequiredEnvironmentException(name)
        }

        fun getEnvRequired(name: String) = System.getenv(name) ?: throw MissingRequiredEnvironmentException(name)
    }
}

class MissingRequiredEnvironmentException(name: String) : Exception("Missing required environment variable $name")
