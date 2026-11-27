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

import io.github.masgzy.ghostlock.vivo.data.ota.zstd.IncompatibleJvmException;
import sun.misc.Unsafe;

import java.lang.reflect.Field;
import java.nio.Buffer;
import java.nio.ByteOrder;

import static java.lang.String.format;

final class UnsafeUtil
{
    public static final Unsafe UNSAFE;

    /* Base offset of byte[] obtained through the accessor
     * instead of the removed sun.misc.Unsafe.ARRAY_BYTE_BASE_OFFSET
     * static field: identical value, resolvable on every ART and JVM
     * this app runs on. Assigned in the static block below, after
     * UNSAFE itself. */
    public static final int BYTE_ARRAY_BASE_OFFSET;
    private static final long ADDRESS_OFFSET;

    private UnsafeUtil() {}

    static {
        ByteOrder order = ByteOrder.nativeOrder();
        if (!order.equals(ByteOrder.LITTLE_ENDIAN)) {
            throw new IncompatibleJvmException(format("Zstandard requires a little endian platform (found %s)", order));
        }

        try {
            Field theUnsafe = Unsafe.class.getDeclaredField("theUnsafe");
            theUnsafe.setAccessible(true);
            UNSAFE = (Unsafe) theUnsafe.get(null);
        }
        catch (Exception e) {
            throw new IncompatibleJvmException("Zstandard requires access to sun.misc.Unsafe");
        }

        BYTE_ARRAY_BASE_OFFSET = UNSAFE.arrayBaseOffset(byte[].class);

        try {
            // fetch the address field for direct buffers
            ADDRESS_OFFSET = UNSAFE.objectFieldOffset(Buffer.class.getDeclaredField("address"));
        }
        catch (NoSuchFieldException e) {
            throw new IncompatibleJvmException("Zstandard requires access to java.nio.Buffer raw address field");
        }
    }

    public static long getAddress(Buffer buffer)
    {
        if (!buffer.isDirect()) {
            throw new IllegalArgumentException("buffer is not direct");
        }

        return UNSAFE.getLong(buffer, ADDRESS_OFFSET);
    }
}
