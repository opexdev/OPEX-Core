package co.nilin.opex.config.core.inout

data class WebConfig(
    val logoUrl: String?,
    val title: String?,
    val description: String?,
    val defaultLanguage: String?,
    val supportedLanguages: List<String>?,
    val defaultTheme: String?,
    val supportEmail: String?,
    val baseCurrency: String?,
    val dateType: String?
)