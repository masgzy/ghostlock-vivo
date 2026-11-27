package io.github.masgzy.ghostlock.vivo.data.ota

import io.airlift.compress.zstd.ZstdOutputStream
import java.io.ByteArrayOutputStream
import java.io.File
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
 * The local full-package parse must read the picked document in place, never
 * copy it: these tests drive [OtaPayloadExtractor] through a
 * [LocalFileRangeReader] over a real temp file, the same way the app parses a
 * picked OTA zip / payload.bin document. The synthetic package encodes
 * partitions with REPLACE_ZSTD (op 14), the way current vendor full packages
 * do.
 */
class LocalFileRangeReaderTest {

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
        out.write(byteArrayOf(0, 0, 0, 0, 0, 0, 0, 2))
        val manifestSize = manifestBytes.size.toLong()
        out.write(byteArrayOf(
            (manifestSize shr 56).toByte(), (manifestSize shr 48).toByte(),
            (manifestSize shr 40).toByte(), (manifestSize shr 32).toByte(),
            (manifestSize shr 24).toByte(), (manifestSize shr 16).toByte(),
            (manifestSize shr 8).toByte(), manifestSize.toByte(),
        ))
        out.write(byteArrayOf(0, 0, 0, 0))
        out.write(manifestBytes)
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

    private fun zstd(data: ByteArray): ByteArray {
        val raw = ByteArrayOutputStream()
        ZstdOutputStream(raw).use { it.write(data) }
        return raw.toByteArray()
    }

    /** boot (REPLACE_ZSTD) + vendor_boot (REPLACE_ZSTD) package as a file. */
    private fun writePackageFile(): Pair<File, Pair<ByteArray, ByteArray>> {
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
        val file = File(tmp.root, "ota.zip")
        file.writeBytes(zip)
        return file to (bootData to vbData)
    }

    @Test
    fun `local OTA zip with replace_zstd partitions is extracted in place`() = runBlocking {
        val (file, expected) = writePackageFile()

        val reader = LocalFileRangeReader(file)
        try {
            assertEquals(file.length(), reader.fileLength("local"))

            val workDir = tmp.newFolder("work")
            val logs = mutableListOf<String>()
            val extracted = OtaPayloadExtractor.extractPartitions(
                url = "local",
                workDir = workDir,
                onLog = { logs.add(it) },
                wantVendorBoot = true,
                reader = reader,
            )
            assertArrayEquals(expected.first, extracted.bootFile.readBytes())
            assertNotNull(extracted.vendorBootFile)
            assertArrayEquals(expected.second, extracted.vendorBootFile!!.readBytes())
            assertTrue(logs.any { it.startsWith("located payload.bin in OTA zip") })
        } finally {
            reader.close()
        }
    }

    @Test
    fun `reader serves short random-access ranges`() = runBlocking {
        val file = File(tmp.root, "blob.bin")
        val data = ByteArray(100_000) { (it * 7).toByte() }
        file.writeBytes(data)
        val reader = LocalFileRangeReader(file)
        try {
            assertArrayEquals(data.copyOfRange(4096, 4096 + 1000), reader.read("local", 4096, 1000))
            /* A read may ask for more than what is left at EOF; the reader
             * returns the remainder, like the HTTP reader does. */
            val tail = reader.read("local", file.length() - 10, 64)
            assertEquals(10, tail?.size)
            assertArrayEquals(data.copyOfRange((file.length() - 10).toInt(), file.length().toInt()), tail)
            /* A fully out-of-range read serves nothing. */
            assertNull(reader.read("local", file.length(), 8))
            assertEquals(0, reader.read("local", 0, 0)?.size)
        } finally {
            reader.close()
        }
    }
}
