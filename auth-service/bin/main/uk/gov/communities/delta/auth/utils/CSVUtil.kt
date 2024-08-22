package uk.gov.communities.delta.auth.utils

private val csvChars = Regex("[,\"\n]")

fun StringBuilder.csvRow(row: List<String>) {
    for (i in row.indices) {
        val element = row[i]
        if (element.contains(csvChars)) {
            append('"')
            append(element.replace("\"", "\"\""))
            append('"')
            if (i < row.size - 1) append(',')
        } else {
            append(element)
            if (i < row.size - 1) append(',')
        }
    }
    append('\n')
}
