#ifndef GHOSTLOCK_BOOTIMG_EXTRACT_H
#define GHOSTLOCK_BOOTIMG_EXTRACT_H

#include "support/native_result.hpp"

#include <cstdint>
#include <span>
#include <vector>

namespace ghostlock::bootimg {

    /* Boot-extraction failures. */
    enum class BootError : int {
        IoError,
        HeaderTooShort,
        UnknownCompression,
        ImageTooSmall,
        ImageHeaderSizeMismatch,
        BadKallsyms,
        BadBtf,
        SymbolNotFound,
        TracepointNotFound,
        VendorBootMissing,
    };

    /* The vr.ko-relevant symbols of a boot image, as link-time virtual
     * addresses straight out of the embedded kallsyms. */
    struct VrSymbols {
        uintptr_t sys_exit_tp = 0;       /* __tracepoint_sys_exit */
        uintptr_t commit_creds_tp = 0;   /* __tracepoint_android_rvh_commit_creds */
        uintptr_t probestub_sys_exit = 0;/* __probestub_sys_exit */
        uintptr_t text_base = 0;         /* _stext (or _text): image offset zero */
    };

    /* Resolve the vr.ko-relevant symbols from a raw boot image:
     *   1. parse_header() -> kernel segment [offset, size)
     *   2. validate the arm64 Image size (vmlinux payload)
     *   3. kallsyms token table -> symbol addresses
     * Partial success is never returned. */
    support::Result<VrSymbols, BootError> extract_vr_symbols(std::span<const std::uint8_t> raw_bootimg);

    /* The single value the W1c global disarm needs, as an *image offset*
     * (relative to _stext): symbol(__tracepoint_sys_exit) - _stext +
     * offsetof(struct tracepoint, funcs), the latter from the embedded BTF
     * (fallback 0x48, the layout of kernels built without
     * CONFIG_HAVE_STATIC_CALL).
     *
     * Image-offset, not link-address, on purpose: the runtime applies the
     * KASLR slide through its own alias arithmetic (the same way a profile's
     * offset.* entries travel), so a recovered value stays correct on
     * randomized kernels where the link address would not. */
    support::Result<uint64_t, BootError> recover_sys_exit_tp_funcs_image(std::span<const std::uint8_t> raw_bootimg);

    /* Load a raw boot image from a device path. */
    support::Result<std::vector<std::uint8_t>, BootError>
    load_boot_image(const char* boot_path, std::size_t max_read = 64 * 1024 * 1024);

    /* Short reason for a boot-image failure, for log lines. */
    inline const char *error_name(BootError error) noexcept {
        switch (error) {
            case BootError::IoError: return "io error";
            case BootError::HeaderTooShort: return "header too short";
            case BootError::UnknownCompression: return "unknown compression";
            case BootError::ImageTooSmall: return "image too small";
            case BootError::ImageHeaderSizeMismatch: return "arm64 image header mismatch";
            case BootError::BadKallsyms: return "kallsyms unrecoverable";
            case BootError::BadBtf: return "btf unrecoverable";
            case BootError::SymbolNotFound: return "symbol not found";
            case BootError::TracepointNotFound: return "tracepoint not found";
            case BootError::VendorBootMissing: return "vendor_boot missing";
        }
        return "unknown";
    }

} // namespace ghostlock::bootimg

#endif // GHOSTLOCK_BOOTIMG_EXTRACT_H
