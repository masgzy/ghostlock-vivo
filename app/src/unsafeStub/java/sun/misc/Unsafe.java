/*
 * Compile-only stub of the platform's @hide sun.misc.Unsafe.
 *
 * The vendored zstd decoder (app/src/main/java/com/ghostlock/app/data/ota/
 * zstd) links against sun.misc.Unsafe, which exists at runtime on every
 * ART build (core-oj) but is absent from android.jar, so javac cannot see
 * it. This stub carries exactly the members the decoder uses, with the
 * standard OpenJDK signatures; it is compiled into a jar wired as
 * compileOnly (see app/build.gradle.kts), never packaged and never
 * executed — at runtime the platform class resolves instead. If a member
 * is missing here, javac fails loudly; nothing silently degrades.
 */
package sun.misc;

public class Unsafe
{
    public static final Unsafe theUnsafe = null;

    public int arrayBaseOffset(Class<?> arrayClass)
    {
        throw new UnsupportedOperationException("stub");
    }

    public int arrayIndexScale(Class<?> arrayClass)
    {
        throw new UnsupportedOperationException("stub");
    }

    public long objectFieldOffset(java.lang.reflect.Field field)
    {
        throw new UnsupportedOperationException("stub");
    }

    public byte getByte(Object base, long offset)
    {
        throw new UnsupportedOperationException("stub");
    }

    public short getShort(Object base, long offset)
    {
        throw new UnsupportedOperationException("stub");
    }

    public int getInt(Object base, long offset)
    {
        throw new UnsupportedOperationException("stub");
    }

    public long getLong(Object base, long offset)
    {
        throw new UnsupportedOperationException("stub");
    }

    public void putByte(Object base, long offset, byte value)
    {
        throw new UnsupportedOperationException("stub");
    }

    public void putShort(Object base, long offset, short value)
    {
        throw new UnsupportedOperationException("stub");
    }

    public void putInt(Object base, long offset, int value)
    {
        throw new UnsupportedOperationException("stub");
    }

    public void putLong(Object base, long offset, long value)
    {
        throw new UnsupportedOperationException("stub");
    }

    public void copyMemory(Object srcBase, long srcOffset, Object destBase, long destOffset, long bytes)
    {
        throw new UnsupportedOperationException("stub");
    }
}
