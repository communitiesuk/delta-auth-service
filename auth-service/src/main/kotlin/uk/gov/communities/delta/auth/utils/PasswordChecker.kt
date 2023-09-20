package uk.gov.communities.delta.auth.utils

import java.util.*

class PasswordChecker {

    private fun containsCommonString(lowerCasePassword: String): Boolean {
        val commonStrings = arrayOf("qwerty", "abcd", "123456", "password")
        for (commonString in commonStrings) {
            if (lowerCasePassword.contains(commonString)) return true
        }
        return false
    }

    private fun hasInsufficientUniqueCharacters(password: String): Boolean {
        val uniqueCharacters: MutableSet<Char> = HashSet()
        for (c in password.toCharArray()) uniqueCharacters.add(c)
        return uniqueCharacters.size < 5
    }

    private fun containsPartOfUserEmail(lowerCasePassword: String, userEmail: String): Boolean {
        val wordsInUserEmail =
            userEmail.lowercase(Locale.getDefault()).split("[\\W0-9_]".toRegex()).dropLastWhile { it.isEmpty() }
                .toTypedArray()
        for (word in wordsInUserEmail) {
            if (lowerCasePassword.contains(word) && word.length > 4) return true
        }
        return false
    }

    fun isCommonPassword(userCN: String, password: String): Boolean {
        val lowerCasePassword = password.lowercase(Locale.getDefault())
        return hasInsufficientUniqueCharacters(password) ||
                containsCommonString(lowerCasePassword) ||
                containsPartOfUserEmail(lowerCasePassword, userCN)
    }
}