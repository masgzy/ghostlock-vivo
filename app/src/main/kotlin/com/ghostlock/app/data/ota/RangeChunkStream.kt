package com.ghostlock.app.data.ota

import java.io.IOException
import java.io.InputStream

/**
 * Sequential [InputStream] over one contiguous byte range of a package,
 * fetched in fixed-size chunks.
 *
 * This is the memory-safety half of the remote full-package fix. The previous
 * shape of the extractor read an operation's whole compressed blob with one
 * `reader.read(url, start, op.dataLength)` call, then decompressed the entire
 * partition with `ZstdInputStream(...).readBytes()` — both steps materialize
 * hundreds of MiB (a vivo full package's boot / vendor_boot) as `ByteArray`s
 * on the ART heap. That allocation is an `OutOfMemoryError`, which is an
 * `Error` and not an `Exception`: no `catch (Exception)` in the parse funnel
 * saw it, and the process died mid-download with the log sheet showing
 * nothing.
 *
 * Wrapping the range in this stream keeps the resident set at one chunk
 * (2 MiB) regardless of the partition size: [read] hands out bytes from the
 * current chunk and pulls the next one only when the previous is drained.
 * The fetch callback bridges to the caller's reader; it may block (HTTP or
 * local channel) but must not require the calling thread.
 */
class RangeChunkStream(
    private val length: Long,
    private val fetch: (start: Long, size: Int) -> ByteArray?,
) : InputStream() {

    private var position = 0L
    private var chunk: ByteArray = ByteArray(0)
    private var chunkOffset = 0
    private var exhausted = false
    private var closed = false

    override fun read(): Int {
        val one = ByteArray(1)
        return if (read(one, 0, 1) == -1) -1 else one[0].toInt() and 0xFF
    }

    override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
        checkNotClosed()
        if (length <= 0) return 0
        if (exhausted) return -1
        if (!fill()) return -1
        val count = minOf(length, chunk.size - chunkOffset)
        System.arraycopy(chunk, chunkOffset, buffer, offset, count)
        chunkOffset += count
        return count
    }

    override fun skip(requested: Long): Long {
        checkNotClosed()
        var remaining = requested
        while (remaining > 0 && !exhausted) {
            if (chunkOffset < chunk.size) {
                val inChunk = minOf(remaining, (chunk.size - chunkOffset).toLong()).toInt()
                chunkOffset += inChunk
                remaining -= inChunk
            } else if (!fill()) {
                break
            }
        }
        return requested - remaining
    }

    override fun available(): Int {
        checkNotClosed()
        return (chunk.size - chunkOffset).coerceAtLeast(0)
    }

    override fun close() {
        closed = true
    }

    private fun checkNotClosed() {
        if (closed) throw IOException("range stream closed")
    }

    /** Fetches the next chunk when the current one is drained; false at EOF. */
    private fun fill(): Boolean {
        if (chunkOffset < chunk.size) return true
        if (position >= length) {
            exhausted = true
            return false
        }
        val want = minOf(CHUNK_SIZE.toLong(), length - position).toInt()
        val next = fetch(position, want)
            ?: throw IOException(
                "short read at +$position (+$want bytes) — the source dropped mid-transfer"
            )
        if (next.isEmpty()) {
            exhausted = true
            return false
        }
        chunk = next
        chunkOffset = 0
        position += next.size
        return true
    }

    private companion object {
        /** One range request's worth of data; small enough that the resident
         * set stays flat across an 8 GiB package. */
        const val CHUNK_SIZE = 2 shl 20
    }
}
