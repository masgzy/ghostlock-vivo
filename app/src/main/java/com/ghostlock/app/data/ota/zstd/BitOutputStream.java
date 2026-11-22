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

import static com.ghostlock.app.data.ota.zstd.Constants.SIZE_OF_LONG;
import static com.ghostlock.app.data.ota.zstd.UnsafeUtil.UNSAFE;
import static com.ghostlock.app.data.ota.zstd.Util.checkArgument;

class BitOutputStream
{
    private static final long[] BIT_MASK = {
            0x0, 0x1, 0x3, 0x7, 0xF, 0x1F,
            0x3F, 0x7F, 0xFF, 0x1FF, 0x3FF, 0x7FF,
            0xFFF, 0x1FFF, 0x3FFF, 0x7FFF, 0xFFFF, 0x1FFFF,
            0x3FFFF, 0x7FFFF, 0xFFFFF, 0x1FFFFF, 0x3FFFFF, 0x7FFFFF,
            0xFFFFFF, 0x1FFFFFF, 0x3FFFFFF, 0x7FFFFFF, 0xFFFFFFF, 0x1FFFFFFF,
            0x3FFFFFFF, 0x7FFFFFFF}; // up to 31 bits

    private final Object outputBase;
    private final long outputAddress;
    private final long outputLimit;

    private long container;
    private int bitCount;
    private long currentAddress;

    public BitOutputStream(Object outputBase, long outputAddress, int outputSize)
    {
        checkArgument(outputSize >= SIZE_OF_LONG, "Output buffer too small");

        this.outputBase = outputBase;
        this.outputAddress = outputAddress;
        outputLimit = this.outputAddress + outputSize - SIZE_OF_LONG;

        currentAddress = this.outputAddress;
    }

    public void addBits(int value, int bits)
    {
        container |= (value & BIT_MASK[bits]) << bitCount;
        bitCount += bits;
    }

    /**
     * Note: leading bits of value must be 0
     */
    public void addBitsFast(int value, int bits)
    {
        container |= ((long) value) << bitCount;
        bitCount += bits;
    }

    public void flush()
    {
        int bytes = bitCount >>> 3;

        UNSAFE.putLong(outputBase, currentAddress, container);
        currentAddress += bytes;

        if (currentAddress > outputLimit) {
            currentAddress = outputLimit;
        }

        bitCount &= 7;
        container >>>= bytes * 8;
    }

    public int close()
    {
        addBitsFast(1, 1); // end mark
        flush();

        if (currentAddress >= outputLimit) {
            return 0;
        }

        return (int) ((currentAddress - outputAddress) + (bitCount > 0 ? 1 : 0));
    }
}
