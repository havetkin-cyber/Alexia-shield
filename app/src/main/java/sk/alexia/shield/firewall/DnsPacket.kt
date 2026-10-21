package sk.alexia.shield.firewall

import kotlin.math.min

/** DNS dopyt vytiahnutý z IPv4/UDP paketu z TUN rozhrania. */
class DnsQuery(
    val srcIp: ByteArray,
    val dstIp: ByteArray,
    val srcPort: Int,
    val dstPort: Int,
    val payload: ByteArray,
    val qname: String,
)

/** Minimalistické spracovanie IPv4 + UDP + DNS bez externých knižníc. */
object DnsPacket {

    fun parse(p: ByteArray, len: Int): DnsQuery? {
        if (len < 28) return null
        val version = (p[0].toInt() shr 4) and 0xF
        if (version != 4) return null
        val ihl = (p[0].toInt() and 0x0F) * 4
        if (ihl < 20 || len < ihl + 8 + 12) return null
        if ((p[9].toInt() and 0xFF) != 17) return null // iba UDP

        val srcPort = u16(p, ihl)
        val dstPort = u16(p, ihl + 2)
        if (dstPort != 53) return null

        val totalLen = min(u16(p, 2), len)
        if (totalLen < ihl + 8 + 12) return null
        val payload = p.copyOfRange(ihl + 8, totalLen)
        val qname = readQName(payload) ?: return null
        return DnsQuery(p.copyOfRange(12, 16), p.copyOfRange(16, 20), srcPort, dstPort, payload, qname)
    }

    /** Odpoveď NXDOMAIN s pôvodnou otázkou. */
    fun nxDomain(q: DnsQuery): ByteArray {
        val end = min(questionEnd(q.payload), q.payload.size)
        val r = q.payload.copyOf(end)
        r[2] = ((q.payload[2].toInt() and 0x79) or 0x80).toByte() // QR=1, ponechaj opcode + RD
        r[3] = 0x83.toByte()                                      // RA=1, RCODE=3 (NXDOMAIN)
        r[4] = 0; r[5] = 1                                        // QDCOUNT = 1
        for (i in 6..11) r[i] = 0                                 // AN/NS/AR = 0
        return r
    }

    /** Zabalí DNS odpoveď späť do IPv4/UDP paketu pre aplikáciu, ktorá sa pýtala. */
    fun wrapResponse(q: DnsQuery, dns: ByteArray, dnsLen: Int): ByteArray {
        val udpLen = 8 + dnsLen
        val total = 20 + udpLen
        val out = ByteArray(total)
        out[0] = 0x45
        put16(out, 2, total)
        out[6] = 0x40 // Don't Fragment
        out[8] = 64   // TTL
        out[9] = 17   // UDP
        System.arraycopy(q.dstIp, 0, out, 12, 4)
        System.arraycopy(q.srcIp, 0, out, 16, 4)
        put16(out, 10, ipChecksum(out, 0, 20))
        put16(out, 20, q.dstPort)
        put16(out, 22, q.srcPort)
        put16(out, 24, udpLen)
        // UDP checksum 0 = nepoužitý (pre IPv4 povolené)
        System.arraycopy(dns, 0, out, 28, dnsLen)
        return out
    }

    private fun readQName(d: ByteArray): String? {
        if (d.size < 13 || u16(d, 4) < 1) return null
        var i = 12
        val sb = StringBuilder()
        while (i < d.size) {
            val l = d[i].toInt() and 0xFF
            if (l == 0) return sb.toString().lowercase()
            if ((l and 0xC0) != 0) return null
            if (i + 1 + l > d.size) return null
            if (sb.isNotEmpty()) sb.append('.')
            sb.append(String(d, i + 1, l, Charsets.ISO_8859_1))
            i += 1 + l
        }
        return null
    }

    private fun questionEnd(d: ByteArray): Int {
        var i = 12
        while (i < d.size) {
            val l = d[i].toInt() and 0xFF
            if (l == 0) return i + 1 + 4
            i += 1 + l
        }
        return d.size
    }

    private fun u16(b: ByteArray, off: Int): Int =
        ((b[off].toInt() and 0xFF) shl 8) or (b[off + 1].toInt() and 0xFF)

    private fun put16(b: ByteArray, off: Int, v: Int) {
        b[off] = ((v shr 8) and 0xFF).toByte()
        b[off + 1] = (v and 0xFF).toByte()
    }

    private fun ipChecksum(b: ByteArray, off: Int, len: Int): Int {
        var sum = 0L
        var i = off
        while (i < off + len - 1) {
            sum += (((b[i].toInt() and 0xFF) shl 8) or (b[i + 1].toInt() and 0xFF)).toLong()
            i += 2
        }
        if (len % 2 == 1) sum += ((b[off + len - 1].toInt() and 0xFF) shl 8).toLong()
        while ((sum shr 16) != 0L) sum = (sum and 0xFFFF) + (sum shr 16)
        return (sum.inv() and 0xFFFF).toInt()
    }
}
