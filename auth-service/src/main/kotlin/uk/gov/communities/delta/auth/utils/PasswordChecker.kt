package uk.gov.communities.delta.auth.utils

import java.util.*

class PasswordChecker {

    private fun containsCommonString(lowerCasePassword: String) =
        listOf("qwerty", "abcd", "123456", "password").any { lowerCasePassword.contains(it) }

    private fun hasInsufficientUniqueCharacters(password: String) = password.toCharArray().distinct().size < 5

    private fun containsPartOfUserEmail(lowerCasePassword: String, userEmail: String): Boolean {
        val wordsInUserEmail = userEmail.lowercase(Locale.getDefault()).split("[\\W0-9_]".toRegex())
        return wordsInUserEmail.any { lowerCasePassword.contains(it) && it.length > 4 }
    }

    fun isCommonPassword(userCN: String, password: String): Boolean {
        val lowerCasePassword = password.lowercase(Locale.getDefault())
        return hasInsufficientUniqueCharacters(password) ||
                containsCommonString(lowerCasePassword) ||
                containsPartOfUserEmail(lowerCasePassword, userCN)
    }
}