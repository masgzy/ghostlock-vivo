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
 * io.github.masgzy.ghostlock.vivo.data.ota.zstd and sun.misc.Unsafe.ARRAY_BYTE_BASE_OFFSET (a public static final
 * int that newer Android ART builds no longer carry, which made the
 * original class die with NoSuchFieldError at first use) replaced by
 * UnsafeUtil.BYTE_ARRAY_BASE_OFFSET computed via
 * Unsafe.arrayBaseOffset(byte[].class). Original file headers below are
 * kept verbatim; the upstream sources are at
 * https://github.com/airlift/aircompressor (tag 2.0.2).
 */
package io.github.masgzy.ghostlock.vivo.data.ota.zstd;

public class MalformedInputException
        extends RuntimeException
{
    private final long offset;

    public MalformedInputException(long offset)
    {
        this(offset, "Malformed input");
    }

    public MalformedInputException(long offset, String reason)
    {
        super(reason + ": offset=" + offset);
        this.offset = offset;
    }

    public long getOffset()
    {
        return offset;
    }
}
