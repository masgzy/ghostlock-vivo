package com.ghostlock.app.data.ota

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import io.airlift.compress.zstd.ZstdInputStream
import org.apache.commons.compress.compressors.bzip2.BZip2CompressorInputStream
import java.io.File
import java.io.IOException
import java.io.OutputStream
import java.io.RandomAccessFile
import java.util.Locale
import kotlin.math.min

/**
 * High-performance streaming OTA partition extractor in pure Kotlin.
 * Downloads only the payload metadata and the blocks needed for boot and xbl_config.
 *
 * Memory model: every operation's data is streamed through [RangeChunkStream]
 * in fixed chunks, so the resident set stays flat no matter how large the
 * package or its partitions are. Only REPLACE_XZ still accumulates one
 * operation's compressed blob (bounded by [XZ_INPUT_LIMIT]) because the
 * pure-Kotlin [XzDecoder] consumes a whole buffer; the sizes that appear in
 * real packages stay well below the cap, and going over it is a clean
 * [IOException] instead of the heap-death the buffered path used to hit.
 */
object OtaPayloadExtractor {

    data class ExtractedPartitions(
        val bootFile: File,
        val xblConfigFile: File? = null,
        /**
         * `vendor_boot` when the payload carries it and the caller asked for
         * it. No offset is derived from this image on the Kotlin side: the
         * native runtime probes the vr.ko module out of its ramdisk, so this
         * is the image the app stages for that probe.
         */
        val vendorBootFile: File? = null,
        /**
         * `uefi` when it was the chosen physical-load source (no `xbl_config`
         * in the package). The runtime keeps this one to cross-check the
         * profile's physical base, so the caller stages it instead of deleting.
         */
        val uefiFile: File? = null,
    )

    private const val END_BYTES_SIZE = 65536
    private const val LOCAL_HEADER_PROBE_SIZE = 256

    /** One operation's compressed input ceiling on the buffered (XZ) path. */
    private const val XZ_INPUT_LIMIT = 768L shl 20

    /** Copy granularity between the range stream and the extent writer. */
    private const val COPY_BUFFER = 256 shl 10

    /** Chunk size of the buffered (XZ) drain loop. */
    private const val DRAIN_CHUNK = 2 shl 20

    /**
     * The physical-load sources are alternatives rather than complements: the
     * xbl_config FDT map is preferred and the uefi table is only pulled when
     * the package carries no xbl_config, so a parse never downloads both.
     */
    private val PhysSourceCandidates = listOf("xbl_config", "uefi")

    /** Everything a full-package parse may want, subject to the rules above. */
    val DefaultCandidates: Set<String> = setOf("boot", "vendor_boot", "xbl_config", "uefi")

    suspend fun extractPartitions(
        url: String,
        workDir: File,
        onLog: (String) -> Unit,
        wantVendorBoot: Boolean = true,
        candidates: Set<String> = DefaultCandidates,
        reader: HttpRangeReader = HttpRangeReader(),
    ): ExtractedPartitions {
        val fileLength = reader.fileLength(url) ?: throw IOException("Failed to connect or determine file length from URL")
        if (fileLength <= 0L) {
            throw IOException("Remote file length is zero or invalid")
        }

        onLog("locating payload metadata (file size: ${formatSize(fileLength)})...")

        // 1. Determine payload.bin start offset within the file
        val payloadStart = locatePayloadStart(reader, url, fileLength, onLog)

        // 2. Read payload header (24 bytes)
        val headerBytes =
            reader.read(url, payloadStart, PayloadBinUtils.HEADER_SIZE) ?: throw IOException("Failed to read payload.bin header at offset $payloadStart")
        val payloadHeader = PayloadBinUtils.parseHeader(headerBytes) ?: throw IOException("Invalid payload.bin header (missing CrAU magic)")

        // 3. Read manifest bytes
        val manifestStart = payloadStart + PayloadBinUtils.HEADER_SIZE
        if (payloadHeader.manifestSize > Int.MAX_VALUE) {
            throw IOException("Payload manifest size exceeds maximum supported memory (${payloadHeader.manifestSize} bytes)")
        }
        val manifest = reader.read(url, manifestStart, payloadHeader.manifestSize.toInt()) ?: throw IOException(
            "Failed to read payload manifest (${
                formatSize(payloadHeader.manifestSize)
            })"
        )

        // 4. Inspect available partitions
        val partitions = PayloadBinUtils.listPartitions(manifest)
        if ("boot" !in partitions) {
            throw IOException("Payload does not contain 'boot' partition (found: ${partitions.joinToString()})")
        }
        /* Decide from the manifest before any data is downloaded: only the
         * partitions this parse actually consumes are pulled, and the ones the
         * runtime does not keep are deleted by the caller afterwards. */
        val physSource = PhysSourceCandidates.firstOrNull { it in partitions && it in candidates }
        val want = buildList {
            add("boot")
            if (wantVendorBoot && "vendor_boot" in partitions && "vendor_boot" in candidates) {
                add("vendor_boot")
            }
            physSource?.let(::add)
        }
        onLog("analyzing partitions: ${want.joinToString(", ")}")
        if (wantVendorBoot && "vendor_boot" !in partitions) {
            onLog("vendor_boot: not present in this package")
        }

        val blockSize = PayloadBinUtils.blockSize(manifest)
        val dataBase = payloadStart + PayloadBinUtils.HEADER_SIZE + payloadHeader.manifestSize + payloadHeader.signatureSize

        // 5. Gather operations for the partitions
        val partitionOps = want.associateWith { name ->
            val ops = PayloadBinUtils.partitionOperations(manifest, name)
            if (ops.isEmpty()) throw IOException("Partition '$name' has no operations in payload")
            ops
        }

        val totalDownloadBytes = partitionOps.values.sumOf { ops -> ops.sumOf { it.dataLength } }
        var currentDownloadedBytes = 0L
        var lastLogTime = 0L

        fun reportProgress(force: Boolean = false) {
            val now = System.currentTimeMillis()
            if (force || now - lastLogTime >= 2000) {
                lastLogTime = now
                val percent = if (totalDownloadBytes > 0) {
                    currentDownloadedBytes.toDouble() / totalDownloadBytes * 100.0
                } else 0.0
                onLog(
                    "download: ${formatSize(currentDownloadedBytes)} / ${
                        formatSize(
                            totalDownloadBytes
                        )
                    } (" + String.format(Locale.US, "%.1f", percent) + "%)"
                )
            }
        }

        // 6. Extract partitions
        val timestamp = System.currentTimeMillis()
        var bootFile: File? = null
        var xblConfigFile: File? = null
        var vendorBootFile: File? = null
        var uefiFile: File? = null

        try {
            for ((name, ops) in partitionOps) {
                val outFile = File(workDir, "ghostlock_ota_${name}_$timestamp.img")
                when (name) {
                    "boot" -> bootFile = outFile
                    "vendor_boot" -> vendorBootFile = outFile
                    "uefi" -> uefiFile = outFile
                    else -> xblConfigFile = outFile
                }

                val totalSize = ops.flatMap { it.destExtents }.maxOfOrNull { (it.startBlock + it.numBlocks) * blockSize }
                    ?: throw IOException("Partition '$name' has zero length")

                withContext(Dispatchers.IO) {
                    /* Visible to the blocking fetch bridge so a cancelled parse
                     * stops at the next chunk instead of running the operation
                     * to its end. */
                    val job = coroutineContext[Job]
                    val fetchAt: (Long, Int) -> ByteArray? = { offset, size ->
                        if (job?.isActive == false) {
                            throw CancellationException("payload extraction cancelled")
                        }
                        runBlocking { reader.read(url, dataBase + offset, size) }
                    }

                    RandomAccessFile(outFile, "rw").use { raf ->
                        raf.setLength(totalSize)

                        for (op in ops) {
                            when (op.type) {
                                PayloadBinUtils.OP_ZERO, PayloadBinUtils.OP_DISCARD -> {
                                    // Already zero-filled by setLength
                                }

                                PayloadBinUtils.OP_REPLACE -> {
                                    /* Raw bytes straight from the wire into the
                                     * extents: no operation-sized buffer ever
                                     * exists. */
                                    val extents = ExtentOutputStream(raf, op.destExtents, blockSize)
                                    RangeChunkStream(op.dataLength) { position, size ->
                                        fetchAt(op.dataOffset + position, size)?.also { chunk ->
                                            currentDownloadedBytes += chunk.size
                                            reportProgress()
                                        }
                                    }.use { input ->
                                        extents.use { output ->
                                            input.copyTo(output, COPY_BUFFER)
                                        }
                                    }
                                }

                                PayloadBinUtils.OP_REPLACE_BZ -> {
                                    val extents = ExtentOutputStream(raf, op.destExtents, blockSize)
                                    RangeChunkStream(op.dataLength) { position, size ->
                                        fetchAt(op.dataOffset + position, size)?.also { chunk ->
                                            currentDownloadedBytes += chunk.size
                                            reportProgress()
                                        }
                                    }.use { input ->
                                        BZip2CompressorInputStream(input).use { decompressed ->
                                            extents.use { output ->
                                                decompressed.copyTo(output, COPY_BUFFER)
                                            }
                                        }
                                    }
                                }

                                PayloadBinUtils.OP_REPLACE_ZSTD -> {
                                    /* The op that killed the buffered path: a
                                     * vivo 8 GiB full package ships boot and
                                     * vendor_boot as single ZSTD blobs whose
                                     * decompressed size is hundreds of MiB.
                                     * The airlift decoder streams, so the
                                     * partition goes chunk-by-chunk onto disk
                                     * and nothing operation-sized is resident. */
                                    val extents = ExtentOutputStream(raf, op.destExtents, blockSize)
                                    RangeChunkStream(op.dataLength) { position, size ->
                                        fetchAt(op.dataOffset + position, size)?.also { chunk ->
                                            currentDownloadedBytes += chunk.size
                                            reportProgress()
                                        }
                                    }.use { input ->
                                        ZstdInputStream(input).use { decompressed ->
                                            extents.use { output ->
                                                decompressed.copyTo(output, COPY_BUFFER)
                                            }
                                        }
                                    }
                                }

                                PayloadBinUtils.OP_REPLACE_XZ -> {
                                    if (op.dataLength > XZ_INPUT_LIMIT) {
                                        throw IOException(
                                            "REPLACE_XZ operation for $name is ${formatSize(op.dataLength)}; " +
                                                "the buffered XZ path supports up to ${formatSize(XZ_INPUT_LIMIT)}"
                                        )
                                    }
                                    val uncompressedSize = op.destExtents.sumOf { it.numBlocks } * blockSize
                                    if (uncompressedSize > Int.MAX_VALUE) {
                                        throw IOException(
                                            "REPLACE_XZ destination for $name (${formatSize(uncompressedSize)}) exceeds the decoder's buffer limit"
                                        )
                                    }
                                    val compressed = drainRange(fetchAt, op.dataOffset, op.dataLength, name)
                                    val decompressed = XzDecoder.decode(compressed, uncompressedSize.toInt())
                                    writeExtents(raf, decompressed, op.destExtents, blockSize)
                                    currentDownloadedBytes += op.dataLength
                                    reportProgress()
                                }

                                else -> {
                                    /* Differential operations (SOURCE_COPY,
                                     * PUFFDIFF, BROTLI_BSDIFF, ZUCCHINI,
                                     * LZ4DIFF_*) need the previous version's
                                     * partition data, which a package link
                                     * does not carry. Full OTA packages never
                                     * contain them; a delta/incremental
                                     * package must go through the full one. */
                                    throw IOException(
                                        "differential payload operation (type ${op.type}, ${PayloadBinUtils.opName(op.type)}) " +
                                            "in partition '$name'; remote parsing supports full OTA packages only — " +
                                            "use the full-package (全量包) link, or parse a local boot.img"
                                    )
                                }
                            }
                        }
                    }
                }
                onLog("extracted $name=${outFile.name} (${formatSize(outFile.length())}) from payload")
            }
            reportProgress(force = true)
            return ExtractedPartitions(bootFile!!, xblConfigFile, vendorBootFile, uefiFile)
        } catch (error: CancellationException) {
            cleanupPartial(bootFile, xblConfigFile, vendorBootFile, uefiFile)
            throw error
        } catch (error: Throwable) {
            /* Cleanup must also run for Errors (OOM and friends): the temp
             * images are half-written and useless, and leaving them behind is
             * what used to burn storage after a crash. */
            cleanupPartial(bootFile, xblConfigFile, vendorBootFile, uefiFile)
            throw error
        }
    }

    /** Deletes the partially written partition images of a failed extract. */
    private fun cleanupPartial(vararg files: File?) {
        files.forEach { it?.delete() }
    }

    /**
     * Reads one operation's whole compressed range into a single buffer (the
     * XZ decoder consumes complete streams). [length] is bounded by the
     * caller against [XZ_INPUT_LIMIT], so this is one allocation of exactly
     * the compressed size.
     */
    private fun drainRange(
        fetchAt: (Long, Int) -> ByteArray?,
        dataOffset: Long,
        length: Long,
        name: String,
    ): ByteArray {
        val out = ByteArray(length.toInt())
        var filled = 0L
        while (filled < length) {
            val want = min(DRAIN_CHUNK.toLong(), length - filled).toInt()
            val chunk = fetchAt(dataOffset + filled, want)
                ?: throw IOException("short read in REPLACE_XZ data for '$name' at +$filled")
            if (chunk.isEmpty()) {
                throw IOException("truncated REPLACE_XZ data for '$name' at +$filled")
            }
            System.arraycopy(chunk, 0, out, filled.toInt(), chunk.size)
            filled += chunk.size
        }
        return out
    }

    private suspend fun locatePayloadStart(
        reader: HttpRangeReader, url: String, fileLength: Long, onLog: (String) -> Unit
    ): Long {
        // Probe head first: is it already a raw payload.bin?
        val headBytes = reader.read(url, 0L, 4)
        if (headBytes != null && headBytes.size >= 4 && headBytes.contentEquals(PayloadBinUtils.PAYLOAD_MAGIC)) {
            onLog("detected direct payload.bin")
            return 0L
        }

        // Locate via ZIP Central Directory
        val tailSize = min(fileLength, END_BYTES_SIZE.toLong()).toInt()
        val tailBytes = reader.read(url, fileLength - tailSize, tailSize) ?: throw IOException("Failed to read ZIP tail from remote file")

        val cd = ZipFileUtils.locateCentralDirectory(tailBytes, fileLength)
        if (cd.offset < 0 || cd.size <= 0 || cd.offset + cd.size > fileLength) {
            throw IOException("Failed to locate ZIP Central Directory in remote file")
        }

        val cdBytes = reader.read(url, cd.offset, cd.size.toInt()) ?: throw IOException("Failed to read ZIP Central Directory (${cd.size} bytes)")

        val entry = ZipFileUtils.locateEntries(
            cdBytes, setOf(PayloadBinUtils.PAYLOAD_ENTRY)
        )[PayloadBinUtils.PAYLOAD_ENTRY] ?: throw IOException("Remote OTA ZIP does not contain '${PayloadBinUtils.PAYLOAD_ENTRY}'")

        if (entry.method != 0) {
            throw IOException("payload.bin in remote ZIP must be Stored (uncompressed), found compression method ${entry.method}")
        }

        val headerOffset = entry.localHeaderOffset
        if (headerOffset !in 0..<fileLength) {
            throw IOException("Invalid local header offset in ZIP: $headerOffset")
        }

        val probeSize = min(fileLength - headerOffset, LOCAL_HEADER_PROBE_SIZE.toLong()).toInt()
        val localHeaderBytes = reader.read(url, headerOffset, probeSize) ?: throw IOException("Failed to read local file header for payload.bin")

        val internalOffset = ZipFileUtils.locateLocalFileOffset(localHeaderBytes)
        if (internalOffset !in 0..probeSize.toLong()) {
            throw IOException("Failed to parse local file header offset for payload.bin")
        }

        val payloadStart = headerOffset + internalOffset
        onLog("located payload.bin in OTA zip at offset $payloadStart (${formatSize(entry.uncompressedSize)})")
        return payloadStart
    }

    private fun writeExtents(
        raf: RandomAccessFile, data: ByteArray, extents: List<PayloadBinUtils.Extent>, blockSize: Long
    ) {
        var dataOffset = 0
        for (extent in extents) {
            val extentBytes = (extent.numBlocks * blockSize).toInt()
            val end = min(dataOffset + extentBytes, data.size)
            if (dataOffset < end) {
                raf.seek(extent.startBlock * blockSize)
                raf.write(data, dataOffset, end - dataOffset)
                dataOffset = end
            }
        }
    }

    /**
     * Sequential writer over one operation's destination extents: bytes 0..n
     * land in extent 0, the next range in extent 1, and so on, with the file
     * position derived per extent. Producing more bytes than the extents hold
     * is a corrupt payload and throws; producing fewer leaves the tail
     * zero-filled (the file was pre-sized), matching the historic
     * [writeExtents] semantics.
     */
    private class ExtentOutputStream(
        private val raf: RandomAccessFile,
        private val extents: List<PayloadBinUtils.Extent>,
        private val blockSize: Long,
    ) : OutputStream() {

        /** Cumulative byte offset where each extent starts; last = capacity. */
        private val boundaries = LongArray(extents.size + 1)
        private var written = 0L

        /** Extent index of [written]; writes are sequential, so it only grows. */
        private var cursor = 0

        init {
            var acc = 0L
            extents.forEachIndexed { index, extent ->
                boundaries[index] = acc
                acc += extent.numBlocks * blockSize
            }
            boundaries[extents.size] = acc
        }

        override fun write(byte: Int) {
            write(byteArrayOf(byte.toByte()), 0, 1)
        }

        override fun write(buffer: ByteArray, offset: Int, length: Int) {
            if (length <= 0) return
            val capacity = boundaries[extents.size]
            if (written + length > capacity) {
                throw IOException(
                    "operation produced ${written + length} bytes but its destination extents hold only $capacity"
                )
            }
            var position = offset
            var remaining = length
            while (remaining > 0) {
                while (cursor < extents.size && written >= boundaries[cursor + 1]) cursor++
                val extentStart = boundaries[cursor]
                val take = min(remaining.toLong(), boundaries[cursor + 1] - written).toInt()
                raf.seek(extents[cursor].startBlock * blockSize + (written - extentStart))
                raf.write(buffer, position, take)
                written += take
                position += take
                remaining -= take
            }
        }
    }

    fun formatSize(bytes: Long): String {
        if (bytes < 0) return "0 B"
        val units = arrayOf("B", "KiB", "MiB", "GiB", "TiB")
        var value = bytes.toDouble()
        var unit = 0
        while (value >= 1024.0 && unit + 1 < units.size) {
            value /= 1024.0
            unit++
        }
        return String.format(Locale.US, "%.1f %s", value, units[unit])
    }
}
