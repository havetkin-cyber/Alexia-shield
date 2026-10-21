package sk.alexia.shield.audit

import android.content.pm.ApplicationInfo

/** Váhy rizikových oprávnení a to, čo je pre daný typ appky „normálne“. */
object PermissionWeights {

    enum class Group { LOCATION, CONTACTS, SMS, CALLS, MIC, CAMERA, CALENDAR, STORAGE, SYSTEM, SENSORS }

    data class Rule(val weight: Int, val label: String, val group: Group)

    private const val P = "android.permission."

    val rules: Map<String, Rule> = mapOf(
        "${P}ACCESS_BACKGROUND_LOCATION" to Rule(25, "Poloha na pozadí", Group.LOCATION),
        "${P}ACCESS_FINE_LOCATION" to Rule(12, "Presná poloha", Group.LOCATION),
        "${P}ACCESS_COARSE_LOCATION" to Rule(6, "Približná poloha", Group.LOCATION),

        "${P}READ_CONTACTS" to Rule(15, "Čítanie kontaktov", Group.CONTACTS),
        "${P}WRITE_CONTACTS" to Rule(8, "Úprava kontaktov", Group.CONTACTS),
        "${P}GET_ACCOUNTS" to Rule(6, "Zoznam účtov", Group.CONTACTS),

        "${P}READ_SMS" to Rule(20, "Čítanie SMS", Group.SMS),
        "${P}RECEIVE_SMS" to Rule(15, "Príjem SMS", Group.SMS),
        "${P}SEND_SMS" to Rule(20, "Odosielanie SMS (môže stáť peniaze)", Group.SMS),

        "${P}READ_CALL_LOG" to Rule(18, "História hovorov", Group.CALLS),
        "${P}CALL_PHONE" to Rule(10, "Volanie bez potvrdenia", Group.CALLS),
        "${P}READ_PHONE_STATE" to Rule(6, "Stav a identita telefónu", Group.CALLS),
        "${P}READ_PHONE_NUMBERS" to Rule(8, "Telefónne číslo", Group.CALLS),
        "${P}ANSWER_PHONE_CALLS" to Rule(10, "Prijímanie hovorov", Group.CALLS),

        "${P}RECORD_AUDIO" to Rule(15, "Mikrofón", Group.MIC),
        "${P}CAMERA" to Rule(12, "Kamera", Group.CAMERA),
        "${P}READ_CALENDAR" to Rule(8, "Kalendár", Group.CALENDAR),

        "${P}READ_EXTERNAL_STORAGE" to Rule(5, "Súbory v úložisku", Group.STORAGE),
        "${P}MANAGE_EXTERNAL_STORAGE" to Rule(18, "Prístup ku všetkým súborom", Group.STORAGE),
        "${P}READ_MEDIA_IMAGES" to Rule(5, "Fotky", Group.STORAGE),
        "${P}READ_MEDIA_VIDEO" to Rule(5, "Videá", Group.STORAGE),

        "${P}SYSTEM_ALERT_WINDOW" to Rule(12, "Prekrývanie iných appiek", Group.SYSTEM),
        "${P}REQUEST_INSTALL_PACKAGES" to Rule(15, "Inštalácia ďalších appiek", Group.SYSTEM),
        "${P}QUERY_ALL_PACKAGES" to Rule(6, "Zoznam všetkých appiek", Group.SYSTEM),
        "${P}PACKAGE_USAGE_STATS" to Rule(8, "Štatistiky používania", Group.SYSTEM),
        "${P}WRITE_SETTINGS" to Rule(8, "Zmena systémových nastavení", Group.SYSTEM),

        "${P}BODY_SENSORS" to Rule(10, "Telesné senzory", Group.SENSORS),
        "${P}ACTIVITY_RECOGNITION" to Rule(5, "Rozpoznanie aktivity", Group.SENSORS),
    )

    /**
     * Skupiny, ktoré daná kategória appky bežne potrebuje.
     * null = kategória neznáma, nesúlad nevyhodnocujeme.
     */
    fun expectedGroups(category: Int): Set<Group>? = when (category) {
        ApplicationInfo.CATEGORY_MAPS -> setOf(Group.LOCATION, Group.STORAGE)
        ApplicationInfo.CATEGORY_SOCIAL ->
            setOf(Group.CONTACTS, Group.CAMERA, Group.MIC, Group.LOCATION, Group.STORAGE, Group.CALLS)
        ApplicationInfo.CATEGORY_VIDEO, ApplicationInfo.CATEGORY_IMAGE ->
            setOf(Group.CAMERA, Group.MIC, Group.STORAGE)
        ApplicationInfo.CATEGORY_AUDIO -> setOf(Group.MIC, Group.STORAGE)
        ApplicationInfo.CATEGORY_PRODUCTIVITY ->
            setOf(Group.CALENDAR, Group.CONTACTS, Group.STORAGE, Group.CAMERA)
        ApplicationInfo.CATEGORY_NEWS -> setOf(Group.STORAGE)
        ApplicationInfo.CATEGORY_GAME -> setOf(Group.STORAGE, Group.SENSORS)
        else -> null
    }
}
