package com.ghostlock.app.data.ota

import android.content.ContentResolver
import android.net.Uri
import android.os.ParcelFileDescriptor
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileInputStream
import java.io.IOException
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.channels.FileChannel

/**
 * Range reader for LOCAL OTA packages (an OTA zip or payload.bin picked
 * through SAF): serves [OtaPayloadExtractor] from a seekable file channel, so
 * the package is parsed in place. An 8 GiB full package is never copied into
 * app storage first — the previous copy into filesDir both burned storage
 * equal to the package size and was the fragile step of the local parse
 * (space exhaustion mid-copy, minutes of silent blocking).
 *
 * Reads are served with [FileChannel.position] + read, which seeks the shared
 * descriptor. The extractor reads strictly sequentially (one read at a time),
 * so the shared position is safe; every read re-seeks anyway.
 */
class LocalFileRangeReader private constructor(
    private val channel: FileChannel,
    private val declaredLength: Long,
    private val closeAction: AutoCloseable,
) : HttpRangeReader() {

    /** A document picked through SAF (OTA zip / payload.bin). */
    constructor(contentResolver: ContentResolver, uri: Uri) : this(
        contentResolver.openFileDescriptor(uri, "r")
            ?: throw IOException("cannot open $uri"),
    )

    private constructor(pfd: ParcelFileDescriptor) : this(
        FileInputStream(pfd.fileDescriptor).channel,
        pfd.statSize,
        AutoCloseable { runCatching { pfd.close() } },
    )

    /** A plain local file (tests, cached images). */
    constructor(file: File) : this(
        RandomAccessFile(file, "r").channel,
        file.length(),
        AutoCloseable { /* closing the channel closes the underlying file */ },
    )

    /** Size of the picked document, from the channel with a stat fallback. */
    override suspend fun fileLength(url: String): Long? = withContext(Dispatchers.IO) {
        runCatching {
            channel.size().takeIf { it > 0 } ?: declaredLength.takeIf { it > 0 }
        }.getOrNull()
    }

    /** One random-access read; returns null when the range cannot be served. */
    override suspend fun read(url: String, offset: Long, length: Int): ByteArray? =
        withContext(Dispatchers.IO) {
            runCatching {
                if (length <= 0) return@runCatching ByteArray(0)
                if (offset < 0) return@runCatching null
                val buffer = ByteBuffer.allocate(length)
                channel.position(offset)
                while (buffer.hasRemaining()) {
                    val read = channel.read(buffer)
                    if (read < 0) break
                }
                /* Short reads at EOF return exactly what was read — a fully
                 * padded array would feed trailing zeros into the extractor's
                 * extent writer; an empty read means the offset was past the
                 * end. */
                val filled = buffer.position()
                when {
                    filled == 0 -> null
                    filled == length -> buffer.array()
                    else -> buffer.array().copyOf(filled)
                }
            }.getOrNull()
        }

    /** Releases the descriptor; idempotent. */
    fun close() {
        runCatching { channel.close() }
        runCatching { closeAction.close() }
    }
}
