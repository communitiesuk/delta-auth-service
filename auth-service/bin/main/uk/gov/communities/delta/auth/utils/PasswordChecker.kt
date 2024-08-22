package uk.gov.communities.delta.auth.utils

import com.google.common.base.Strings
import io.ktor.server.application.*
import io.ktor.server.request.*
import java.util.*

class PasswordChecker {

    private fun containsCommonString(lowerCasePassword: String) =
        listOf("qwerty", "abcd", "123456", "password").any { lowerCasePassword.contains(it) }

    private fun hasInsufficientUniqueCharacters(password: String) = password.toCharArray().distinct().size < 5

    private fun containsPartOfUserEmail(lowerCasePassword: String, userEmail: String): Boolean {
        val wordsInUserEmail = userEmail.lowercase(Locale.getDefault()).split("[\\W0-9_]".toRegex())
        return wordsInUserEmail.any { lowerCasePassword.contains(it) && it.length > 4 }
    }

    suspend fun checkPasswordForErrors(call: ApplicationCall, userEmail: String): Pair<String?, String> {
        val formParameters = call.receiveParameters()
        val newPassword = formParameters["newPassword"].orEmpty()
        val confirmPassword = formParameters["confirmPassword"].orEmpty()
        val lowerCasePassword = newPassword.lowercase(Locale.getDefault())

        val message = if (Strings.isNullOrEmpty(newPassword)) "New password is required."
        else if (Strings.isNullOrEmpty(confirmPassword)) "Confirm password is required."
        else if (newPassword != confirmPassword) "Passwords did not match."
        else if (newPassword.length < 12) "Password must be at least 12 characters long."
        else if (hasInsufficientUniqueCharacters(newPassword)) "Password must have more variation in characters"
        else if (containsCommonString(lowerCasePassword)) "Password must not be a commonly used password."
        else if (containsPartOfUserEmail(
                lowerCasePassword,
                userEmail
            )
        ) "Password must not contain any part(s) your username"
        else null

        return Pair(message, newPassword)
    }
}
