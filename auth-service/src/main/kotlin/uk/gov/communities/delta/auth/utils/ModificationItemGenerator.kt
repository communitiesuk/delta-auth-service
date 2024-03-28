package uk.gov.communities.delta.auth.utils

import javax.naming.directory.BasicAttribute
import javax.naming.directory.DirContext
import javax.naming.directory.ModificationItem

fun getModificationItem(
    parameterName: String,
    currentValue: String?,
    newValue: String?
): ModificationItem? {
    return if (!currentValue.equals(newValue)) {
        if (currentValue.isNullOrEmpty())
            if (newValue.isNullOrEmpty()) null
            else ModificationItem(DirContext.ADD_ATTRIBUTE, BasicAttribute(parameterName, newValue))
        else if (newValue.isNullOrEmpty())
            ModificationItem(DirContext.REMOVE_ATTRIBUTE, BasicAttribute(parameterName))
        else
            ModificationItem(DirContext.REPLACE_ATTRIBUTE, BasicAttribute(parameterName, newValue))
    } else null
}
