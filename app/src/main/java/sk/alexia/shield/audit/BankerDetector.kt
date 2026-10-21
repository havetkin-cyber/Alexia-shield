package sk.alexia.shield.audit

/**
 * Heuristika na bankové trójske kone (Anatsa, Cerberus, Hydra, SharkBot, Octo…).
 *
 * Takmer všetky kombinujú službu prístupnosti (čítanie a ovládanie obrazovky) s ďalšími
 * schopnosťami: prekrývanie iných appiek (falošné prihlasovacie okná), čítanie SMS
 * (kódy z banky), správca zariadenia (ťažké odinštalovanie) a inštalácia ďalších appiek.
 */
object BankerDetector {

    data class Signals(
        val accessibility: Boolean,
        val accessibilityEnabled: Boolean,
        val overlay: Boolean,
        val sms: Boolean,
        val deviceAdmin: Boolean,
        val installsApps: Boolean,
        val sideloaded: Boolean,
    )

    data class Verdict(val points: Int, val text: String)

    fun evaluate(s: Signals): Verdict? {
        if (!s.accessibility) return null
        val extras = buildList {
            if (s.overlay) add("prekrýva iné appky")
            if (s.sms) add("číta SMS")
            if (s.deviceAdmin) add("správca zariadenia")
            if (s.installsApps) add("inštaluje appky")
            if (s.sideloaded) add("mimo obchodu")
        }
        // Prístupnosť + aspoň jedna z kľúčových (prekrývanie / SMS) + spolu aspoň 3 signály
        if (!(s.overlay || s.sms) || extras.size < 3) return null

        val detail = "prístupnosť" + (if (s.accessibilityEnabled) " (ZAPNUTÁ)" else "") +
            ", " + extras.joinToString(", ")
        return if (s.accessibilityEnabled) {
            Verdict(60, "⚠️ Správa sa ako bankový trójsky kôň: $detail")
        } else {
            Verdict(30, "Profil podobný bankovému trójskemu koňovi: $detail")
        }
    }
}
