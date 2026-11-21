package com.ghostlock.app.data.ota

import io.airlift.compress.zstd.ZstdOutputStream
import java.io.ByteArrayOutputStream
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * End-to-end coverage for the streaming OTA extractor against an in-memory
 * package: a stored `payload.bin` inside a ZIP, with partitions encoded the
 * same way vendor full packages encode them. The focus is the operation types
 * the Kotlin path must handle on its own (the Rust extractor covers the local
 * file path), in particular REPLACE_ZSTD (type 14) — newer full packages ship
 * every partition that way, and the extractor used to refuse them with
 * "Unsupported payload operation type: 14".
 */
class OtaPayloadExtractorTest {

    @get:Rule
    val tmp = TemporaryFolder()

    /* ---- minimal protobuf writer (matches PayloadBinUtils' reader) ---- */

    private fun varint(value: Long): ByteArray {
        var v = value
        val out = ByteArrayOutputStream()
        while (true) {
            val b = (v and 0x7F).toByte()
            v = v ushr 7
            if (v == 0L) {
                out.write(b.toInt()); break
            }
            out.write((b.toInt() or 0x80))
        }
        return out.toByteArray()
    }

    private fun tag(field: Int, wire: Int) = varint((field.toLong() shl 3) or wire.toLong())

    private fun lenDelim(field: Int, payload: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(tag(field, 2))
        out.write(varint(payload.size.toLong()))
        out.write(payload)
        return out.toByteArray()
    }

    private fun varintField(field: Int, value: Long) = tag(field, 0) + varint(value)

    private fun extent(startBlock: Long, numBlocks: Long): ByteArray =
        varintField(1, startBlock) + varintField(2, numBlocks)

    private fun operation(type: Long, dataOffset: Long, dataLength: Long, vararg extents: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(varintField(1, type))
        out.write(varintField(2, dataOffset))
        out.write(varintField(3, dataLength))
        for (e in extents) out.write(lenDelim(6, e))
        return out.toByteArray()
    }

    private fun partition(name: String, vararg ops: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(lenDelim(1, name.toByteArray(Charsets.UTF_8)))
        for (op in ops) out.write(lenDelim(8, op))
        return out.toByteArray()
    }

    private fun manifest(blockSize: Long, vararg partitions: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(varintField(3, blockSize))
        for (p in partitions) out.write(lenDelim(13, p))
        return out.toByteArray()
    }

    /** Partition blob staging area: the ops' data concatenated. */
    private class BlobArea {
        val bytes = ByteArrayOutputStream()
        private var offset = 0L
        fun append(data: ByteArray): Long {
            val at = offset
            bytes.write(data)
            offset += data.size
            return at
        }
    }

    private fun payload(manifestBytes: ByteArray, blob: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(byteArrayOf('C'.code.toByte(), 'r'.code.toByte(), 'A'.code.toByte(), 'U'.code.toByte()))
        out.write(byteArrayOf(0, 0, 0, 0, 0, 0, 0, 2)) // version 2
        val m = manifestBytes
        out.write(byteArrayOf(
            (m.size ushr 56).toByte(), (m.size ushr 48).toByte(),
            (m.size ushr 40).toByte(), (m.size ushr 32).toByte(),
            (m.size ushr 24).toByte(), (m.size ushr 16).toByte(),
            (m.size ushr 8).toByte(), m.size.toByte(),
        ))
        out.write(byteArrayOf(0, 0, 0, 0)) // signature size
        out.write(m)
        out.write(blob)
        return out.toByteArray()
    }

    /** ZIP with one STORED entry, like an OEM full package. */
    private fun storedZip(entryName: String, data: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        ZipOutputStream(out).use { zip ->
            val entry = ZipEntry(entryName).apply {
                method = ZipEntry.STORED
                size = data.size.toLong()
                compressedSize = data.size.toLong()
                crc = CRC32().apply { update(data) }.value
            }
            zip.putNextEntry(entry)
            zip.write(data)
            zip.closeEntry()
        }
        return out.toByteArray()
    }

    /** Serves the whole ZIP from memory. */
    private class InMemoryReader(private val file: ByteArray) : HttpRangeReader() {
        override suspend fun fileLength(url: String): Long = file.size.toLong()
        override suspend fun read(url: String, start: Long, size: Int): ByteArray? {
            if (start < 0 || start >= file.size) return ByteArray(0)
            val end = minOf(start + size, file.size.toLong()).toInt()
            return file.copyOfRange(start.toInt(), end)
        }
    }

    private fun zstd(data: ByteArray): ByteArray {
        val raw = ByteArrayOutputStream()
        ZstdOutputStream(raw).use { it.write(data) }
        return raw.toByteArray()
    }

    /* ---- tests ---- */

    @Test
    fun `replace_zstd boot and vendor_boot partitions are extracted`() = runBlocking {
        val blockSize = 4096L
        val blobs = BlobArea()

        val bootData = ByteArray(blockSize.toInt() * 2) { (it * 31).toByte() }
        val bootZ = zstd(bootData)
        val bootOff = blobs.append(bootZ)
        val vbData = ByteArray(blockSize.toInt()) { (it * 17).toByte() }
        val vbZ = zstd(vbData)
        val vbOff = blobs.append(vbZ)

        val m = manifest(
            blockSize,
            partition(
                "boot",
                operation(PayloadBinUtils.OP_REPLACE_ZSTD, bootOff, bootZ.size.toLong(), extent(0, 2)),
            ),
            partition(
                "vendor_boot",
                operation(PayloadBinUtils.OP_REPLACE_ZSTD, vbOff, vbZ.size.toLong(), extent(0, 1)),
            ),
        )
        val zip = storedZip("payload.bin", payload(m, blobs.bytes.toByteArray()))

        val logs = mutableListOf<String>()
        val result = OtaPayloadExtractor.extractPartitions(
            url = "https://example.invalid/ota.zip",
            workDir = tmp.root,
            onLog = { logs.add(it) },
            reader = InMemoryReader(zip),
        )

        assertArrayEquals(bootData, result.bootFile.readBytes())
        assertArrayEquals(vbData, result.vendorBootFile!!.readBytes())
        assertNull(result.xblConfigFile)
        assertTrue(logs.any { it.startsWith("analyzing partitions: boot, vendor_boot") })
    }

    @Test
    fun `uefi is pulled only when the package has no xbl_config`() = runBlocking {
        val blockSize = 4096L
        val blobs = BlobArea()

        val bootData = ByteArray(blockSize.toInt()) { 'B'.code.toByte() }
        val bootOff = blobs.append(bootData) // raw REPLACE
        val uefiData = ByteArray(blockSize.toInt()) { 'U'.code.toByte() }
        val uefiOff = blobs.append(uefiData)

        val m = manifest(
            blockSize,
            partition("boot", operation(PayloadBinUtils.OP_REPLACE, bootOff, bootData.size.toLong(), extent(0, 1))),
            partition("uefi", operation(PayloadBinUtils.OP_REPLACE, uefiOff, uefiData.size.toLong(), extent(0, 1))),
        )
        val zip = storedZip("payload.bin", payload(m, blobs.bytes.toByteArray()))

        val result = OtaPayloadExtractor.extractPartitions(
            url = "https://example.invalid/ota.zip",
            workDir = tmp.root,
            onLog = {},
            reader = InMemoryReader(zip),
        )

        assertArrayEquals(bootData, result.bootFile.readBytes())
        assertNotNull(result.uefiFile)
        assertArrayEquals(uefiData, result.uefiFile!!.readBytes())
        assertNull(result.xblConfigFile)
    }

    @Test
    fun `vendor_boot is skipped on request`() = runBlocking {
        val blockSize = 4096L
        val blobs = BlobArea()
        val bootData = ByteArray(blockSize.toInt()) { 7 }
        val bootOff = blobs.append(bootData)
        val m = manifest(
            blockSize,
            partition("boot", operation(PayloadBinUtils.OP_REPLACE, bootOff, bootData.size.toLong(), extent(0, 1))),
            partition("vendor_boot", operation(PayloadBinUtils.OP_REPLACE, 0, 1, extent(0, 1))),
        )
        val zip = storedZip("payload.bin", payload(m, blobs.bytes.toByteArray()))

        val result = OtaPayloadExtractor.extractPartitions(
            url = "https://example.invalid/ota.zip",
            workDir = tmp.root,
            onLog = {},
            wantVendorBoot = false,
            reader = InMemoryReader(zip),
        )

        assertNull(result.vendorBootFile)
        assertEquals(1, tmp.root.listFiles()!!.count { it.name.startsWith("ghostlock_ota_") })
    }

    @Test
    fun `manifest with op type 14 is parsed instead of rejected`() {
        // The reader must surface type 14 operations (REPLACE_ZSTD) rather than
        // dropping them: this is the regression behind "Unsupported payload
        // operation type: 14 in partition 'boot'".
        val blockSize = 4096L
        val m = manifest(
            blockSize,
            partition("boot", operation(PayloadBinUtils.OP_REPLACE_ZSTD, 0, 4096, extent(0, 1))),
        )
        val ops = PayloadBinUtils.partitionOperations(m, "boot")
        assertEquals(1, ops.size)
        assertEquals(PayloadBinUtils.OP_REPLACE_ZSTD, ops[0].type)
        assertEquals(4096L, ops[0].dataLength)
    }
}
