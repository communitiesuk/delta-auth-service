package uk.gov.communities.delta.auth.config

class Env {
    companion object {
        val devFallbackEnabled = getEnv("DISABLE_DEVELOPMENT_FALLBACK") != "true"

        fun getEnv(name: String): String? = System.getenv(name)

        fun getRequiredOrDevFallback(name: String, fallback: String) = getRequiredOrDevFallback(name) { fallback }

        fun getRequiredOrNullDevFallback(name: String): String? {
            val env = getEnv(name)
            if (!env.isNullOrEmpty()) return env
            return if (devFallbackEnabled) null else throw MissingRequiredEnvironmentException(name)
        }

        fun getRequiredOrDevFallback(name: String, fallback: () -> String): String {
            val env = getEnv(name)
            if (!env.isNullOrEmpty()) return env
            return if (devFallbackEnabled) fallback() else throw MissingRequiredEnvironmentException(name)
        }

        fun getOptionalOrDevFallback(name: String, fallback: String) = getOptionalOrDevFallback(name) { fallback }

        fun getOptionalOrDevFallback(name: String, fallback: () -> String): String? {
            val env = getEnv(name)
            if (!env.isNullOrEmpty()) return env
            return if (devFallbackEnabled) fallback() else env
        }

        fun getRequired(name: String) = System.getenv(name) ?: throw MissingRequiredEnvironmentException(name)
    }
}

class MissingRequiredEnvironmentException(name: String) : Exception("Missing required environment variable $name")
