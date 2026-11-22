/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * Vendored from io.airlift:aircompressor 2.0.2 (Apache License 2.0), zstd
 * package, by scripts vendor-aircompressor-zstd: package renamed to
 * com.ghostlock.app.data.ota.zstd and sun.misc.Unsafe.ARRAY_BYTE_BASE_OFFSET (a public static final
 * int that newer Android ART builds no longer carry, which made the
 * original class die with NoSuchFieldError at first use) replaced by
 * UnsafeUtil.BYTE_ARRAY_BASE_OFFSET computed via
 * Unsafe.arrayBaseOffset(byte[].class). Original file headers below are
 * kept verbatim; the upstream sources are at
 * https://github.com/airlift/aircompressor (tag 2.0.2).
 */
package com.ghostlock.app.data.ota.zstd;

import java.util.Objects;
import java.util.StringJoiner;

import static com.ghostlock.app.data.ota.zstd.Util.checkState;
import static java.lang.Math.min;
import static java.lang.Math.toIntExact;

class FrameHeader
{
    final long headerSize;
    final int windowSize;
    final long contentSize;
    final long dictionaryId;
    final boolean hasChecksum;

    public FrameHeader(long headerSize, int windowSize, long contentSize, long dictionaryId, boolean hasChecksum)
    {
        checkState(windowSize >= 0 || contentSize >= 0, "Invalid frame header: contentSize or windowSize must be set");
        this.headerSize = headerSize;
        this.windowSize = windowSize;
        this.contentSize = contentSize;
        this.dictionaryId = dictionaryId;
        this.hasChecksum = hasChecksum;
    }

    public int computeRequiredOutputBufferLookBackSize()
    {
        if (contentSize < 0) {
            return windowSize;
        }
        if (windowSize < 0) {
            return toIntExact(contentSize);
        }
        return toIntExact(min(windowSize, contentSize));
    }

    @Override
    public boolean equals(Object o)
    {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        FrameHeader that = (FrameHeader) o;
        return headerSize == that.headerSize &&
                windowSize == that.windowSize &&
                contentSize == that.contentSize &&
                dictionaryId == that.dictionaryId &&
                hasChecksum == that.hasChecksum;
    }

    @Override
    public int hashCode()
    {
        return Objects.hash(headerSize, windowSize, contentSize, dictionaryId, hasChecksum);
    }

    @Override
    public String toString()
    {
        return new StringJoiner(", ", FrameHeader.class.getSimpleName() + "[", "]")
                .add("headerSize=" + headerSize)
                .add("windowSize=" + windowSize)
                .add("contentSize=" + contentSize)
                .add("dictionaryId=" + dictionaryId)
                .add("hasChecksum=" + hasChecksum)
                .toString();
    }
}
