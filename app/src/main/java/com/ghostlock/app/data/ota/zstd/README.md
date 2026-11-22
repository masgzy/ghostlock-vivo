# Vendored zstd streaming decoder (from aircompressor 2.0.2)

These 22 files are the decode closure of `io.airlift:aircompressor` 2.0.2's
zstd package (Apache License 2.0; original headers kept in every file,
upstream at https://github.com/airlift/aircompressor, tag 2.0.2), vendored by
`/home/z/my-project/scripts/vendor_aircompressor_zstd.py`.

## Why vendor instead of depending on the artifact

`ZstdInputStream` and five of its dependencies statically import
`sun.misc.Unsafe.ARRAY_BYTE_BASE_OFFSET`. That is a `getstatic` link of a
public static final int: javac inlines it on desktop JVMs (so the artifact
works everywhere it is normally tested), but ART resolves it at runtime — and
newer ART builds (the vivo full-package target among them) no longer carry the
field. The first REPLACE_ZSTD operation of a remote OTA parse then died with

```
No field ARRAY_BYTE_BASE_OFFSET of type I in class Lsun/misc/Unsafe;
or its superclasses
```

which the parse funnel reported as a clean failure after the earlier OOM fix.
Up to and including aircompressor 2.0.3 (latest at vendoring time) the import
is unchanged, so a version bump cannot fix it.

## The patch

Exactly one semantic change: `ARRAY_BYTE_BASE_OFFSET` (the removed Unsafe
static field) is replaced by `UnsafeUtil.BYTE_ARRAY_BASE_OFFSET`, an int
assigned in UnsafeUtil's static block **after** `theUnsafe` is obtained:

```java
BYTE_ARRAY_BASE_OFFSET = UNSAFE.arrayBaseOffset(byte[].class);
```

`Unsafe.arrayBaseOffset(byte[].class)` is the accessor the field was a
constant for; it exists on every ART and JVM this app runs on and returns the
identical value. Everything else — including the `theUnsafe` / `Buffer.address`
reflection in UnsafeUtil, which still resolves fine on those ART builds — is
upstream code, unmodified. Package renamed to
`com.ghostlock.app.data.ota.zstd` so it cannot collide with the
test-scoped aircompressor artifact that still provides the zstd *compressor*
used to build unit-test fixtures.
