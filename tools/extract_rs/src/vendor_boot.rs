//! `vendor_boot.img` header parsing (MediaTek only): recover
//! `kernel_phys_load` / `kernel_phys_offset` without root, from the stock
//! image alone.
use std::path::Path;

use crate::error::{ExtractError, Result};

const VNDRBOOT_MAGIC: &[u8; 8] = b"VNDRBOOT";

// No 32 Bit support, Just use 64 Bit text align
const ARM64_TEXT_ALIGN: u64 = 0x8_0000; // 512 KiB

/// Reads `vendor_boot.img`'s `kernel_addr` field and derives
/// `kernel_phys_load`, plus `kernel_phys_offset` when the alignment pattern
/// proves it rather than merely being consistent with it.
pub fn recover_kernel_phys_from_vendor_boot(path: &Path) -> Result<(u64, Option<u64>)> {
    let mut header = [0u8; 20];
    let mut file = std::fs::File::open(path)?;
    std::io::Read::read_exact(&mut file, &mut header)?;
    parse_vendor_boot_header(&header)
}

/// Layout (`vendor_boot_img_hdr_v3/v4` common prefix, little-endian):
/// `magic[8] header_version[4] page_size[4] kernel_addr[4] ...`
fn parse_vendor_boot_header(data: &[u8]) -> Result<(u64, Option<u64>)> {
    if data.len() < 20 || &data[0..8] != VNDRBOOT_MAGIC {
        return Err(ExtractError::new(
            "not a vendor_boot.img (missing VNDRBOOT magic)",
        ));
    }
    let header_version = u32::from_le_bytes(data[8..12].try_into().unwrap());
    let kernel_addr = u32::from_le_bytes(data[16..20].try_into().unwrap()) as u64;
    if header_version < 3 {
        return Err(ExtractError::new(format!(
            "unexpected vendor_boot header_version={header_version} (expected >= 3)"
        )));
    }
    classify(kernel_addr)
}

/// `kernel_phys_load = kernel_addr` (vendor_boot carries no separate base
/// field; it is already the combined physical load address).
///
/// `kernel_phys_offset` (the DRAM base) is only ever returned when the
/// low-20-bit pattern *proves* it, not merely when it is consistent with it:
/// - `low == ARM64_TEXT_ALIGN` unambiguously means `phys_load = dram_base +
///   ARM64_TEXT_ALIGN`, so `phys_offset = phys_load - ARM64_TEXT_ALIGN`.
/// - `low == 0` only tells us `phys_load` is MiB-aligned. That is true both
///   when `phys_load == dram_base` *and* when the kernel is loaded some
///   whole number of MiB above the base (e.g. `phys_load=0x40200000` above
///   `dram_base=0x40000000`). Without a second, independent source (e.g.
///   `/proc/iomem`) we cannot tell those apart, so we return `phys_load`
///   with no offset rather than guessing one.
fn classify(phys_load: u64) -> Result<(u64, Option<u64>)> {
    let low = phys_load & 0xF_FFFF;
    let phys_offset = if low == ARM64_TEXT_ALIGN {
        Some(phys_load - ARM64_TEXT_ALIGN)
    } else if low == 0 {
        None
    } else {
        return Err(ExtractError::new(format!(
            "kernel_phys_load=0x{phys_load:x} matches neither known MediaTek \
             alignment pattern (low 20 bits=0x{low:05x}); refusing to guess \
             kernel_phys_offset"
        )));
    };
    Ok((phys_load, phys_offset))
}

/// Result of the vendor_boot vr.ko probe (hmascs PR #257, ported).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VrKoProbe {
    /// cpio path of the module entry that was probed.
    pub module_path: String,
    /// task_struct byte offset vivo's vr.ko reads for tag A (0x06 family).
    pub tag_a_offset: u32,
    /// task_struct byte offset vivo's vr.ko reads for tag B (0x2c family).
    pub tag_b_offset: u32,
}

/// Walk `vendor_boot.img` -> vendor_ramdisk (LZ4-legacy) -> cpio newc ->
/// `lib/modules/vr.ko` -> ELF executable sections, and recover the two
/// task_struct tag offsets the module's de-tag code reads.
///
/// The tag code is one `mrs xN, sp_el0` followed by byte accesses through
/// that same register: the first immediate is tag A, the next different one
/// is tag B. The window is 8 instructions, which is what the measured
/// families (6.1 / 6.6 / 6.12) fit into.
///
/// Ported from hmascs' PR #257 physmap.cpp (vivo vr.ko neutralization
/// research); the LZ4 frame decoder is boot.rs's own.
pub fn probe_vrko(vendor_boot_img: &[u8]) -> Result<VrKoProbe> {
    if vendor_boot_img.len() < 2124 {
        return Err(ExtractError::new("file is smaller than a vendor_boot header"));
    }
    if &vendor_boot_img[0..8] != VNDRBOOT_MAGIC {
        return Err(ExtractError::new(
            "not a VNDRBOOT image (boot.img and init_boot.img are different partitions)",
        ));
    }
    let rd_u32 = |off: usize| -> u32 {
        u32::from_le_bytes(vendor_boot_img[off..off + 4].try_into().unwrap())
    };
    let header_version = rd_u32(8);
    if !(3..=4).contains(&header_version) {
        return Err(ExtractError::new(format!(
            "unsupported vendor_boot header version {header_version} (only v3/v4 carry a ramdisk)"
            )));
    }
    let page_size = rd_u32(12);
    if page_size == 0 || page_size > 65536 {
        return Err(ExtractError::new("implausible page size in the vendor_boot header"));
    }
    let ramdisk_size = rd_u32(24) as usize;
    if ramdisk_size == 0 {
        return Err(ExtractError::new("the image carries no vendor_ramdisk"));
    }
    // vendor_boot_img_hdr_v4 places header_size at 2096; v3 predates the
    // field and the page-aligned header page is the boundary.
    let mut header_size = rd_u32(2096) as usize;
    let page_size = page_size as usize;
    if header_size == 0 {
        header_size = page_size;
    }
    let ramdisk_start = header_size.div_ceil(page_size) * page_size;
    let ramdisk_end = ramdisk_start
        .checked_add(ramdisk_size)
        .ok_or_else(|| ExtractError::new("vendor_ramdisk size overflows"))?;
    if ramdisk_end > vendor_boot_img.len() {
        return Err(ExtractError::new(
            "the declared ramdisk runs past the end of the file (truncated image?)",
        ));
    }
    const MAX_RAMDISK: usize = 512 * 1024 * 1024;
    let ramdisk = crate::boot::decompress_lz4_legacy_frame(&vendor_boot_img[ramdisk_start..ramdisk_end])
        .map_err(|err| ExtractError::new(format!("vendor_ramdisk is not a decodable LZ4-legacy stream: {err}")))?;
    if ramdisk.len() > MAX_RAMDISK {
        return Err(ExtractError::new("decompressed vendor_ramdisk exceeds 512 MiB"));
    }

    // cpio newc walk; only module entries are retained.
    let mut entries: Vec<(String, usize, usize)> = Vec::new();
    let mut i = 0usize;
    while i + 110 <= ramdisk.len() {
        if &ramdisk[i..i + 6] != b"070701" {
            break;
        }
        // cpio newc fields are fixed 8-char hex; a variable-width parse would
        // swallow the next field's digits.
        let parse_hex8 = |at: usize| -> Option<u32> {
            let mut value = 0u32;
            for k in 0..8 {
                let c = ramdisk[at + k];
                let digit = match c {
                    b'0'..=b'9' => u32::from(c - b'0'),
                    b'a'..=b'f' => u32::from(c - b'a') + 10,
                    b'A'..=b'F' => u32::from(c - b'A') + 10,
                    _ => return None,
                };
                value = (value << 4) | digit;
            }
            Some(value)
        };
        let filesize = parse_hex8(i + 54).unwrap_or(0) as usize;
        let namesize = parse_hex8(i + 94).unwrap_or(0) as usize;
        if namesize == 0 || namesize > 4096 {
            break;
        }
        let name_start = i + 110;
        if name_start + namesize > ramdisk.len() {
            break;
        }
        let name = String::from_utf8_lossy(&ramdisk[name_start..name_start + namesize - 1]).into_owned();
        if name == "TRAILER!!!" {
            break;
        }
        let data_off = (name_start + namesize + 3) & !3usize;
        let next = (data_off + filesize + 3) & !3usize;
        if data_off + filesize > ramdisk.len() {
            break;
        }
        if name.starts_with("lib/modules/") && name.contains("/vr.ko") {
            entries.push((name, data_off, filesize));
        }
        i = next;
    }
    if entries.is_empty() {
        return Err(ExtractError::new(
            "no lib/modules/vr.ko inside the vendor_ramdisk \
             (this device may not ship the anti-root module)",
        ));
    }
    // The flat path is what modprobe resolves for a full `<uname -r>` name.
    let chosen = entries
        .iter()
        .find(|(name, _, _)| name == "lib/modules/vr.ko")
        .unwrap_or(&entries[0]);
    let (module_path, ko_off, ko_len) = chosen.clone();
    let ko = &ramdisk[ko_off..ko_off + ko_len];

    if ko.len() < 64 || ko[0] != 0x7f || ko[1] != b'E' || ko[2] != b'L' || ko[3] != b'F' {
        return Err(ExtractError::new(
            "the module extracted from the ramdisk is not an ELF object",
        ));
    }
    let shoff = u64::from_le_bytes(ko[0x28..0x30].try_into().unwrap()) as usize;
    let shentsize = u16::from_le_bytes(ko[0x3a..0x3c].try_into().unwrap()) as usize;
    let shnum = u16::from_le_bytes(ko[0x3c..0x3e].try_into().unwrap()) as usize;
    if shoff == 0 || shentsize < 64 || shnum == 0 {
        return Err(ExtractError::new("the module has no usable ELF section table"));
    }

    for s in 0..shnum {
        let off = shoff + s * shentsize;
        if off + 64 > ko.len() {
            break;
        }
        let sect_type = u32::from_le_bytes(ko[off + 4..off + 8].try_into().unwrap());
        let flags = u64::from_le_bytes(ko[off + 8..off + 16].try_into().unwrap());
        let sect_off = u64::from_le_bytes(ko[off + 0x18..off + 0x20].try_into().unwrap()) as usize;
        let sect_size = u64::from_le_bytes(ko[off + 0x20..off + 0x28].try_into().unwrap()) as usize;
        // SHT_PROGBITS with SHF_EXECINSTR
        if sect_type != 1 || (flags & 0x4) == 0 || sect_size == 0 {
            continue;
        }
        if sect_off.checked_add(sect_size).map_or(true, |end| end > ko.len()) {
            continue;
        }
        let section = &ko[sect_off..sect_off + sect_size];

        let mut j = 0usize;
        while j + 4 <= section.len() {
            let insn = u32::from_le_bytes(section[j..j + 4].try_into().unwrap());
            // mrs xN, sp_el0 (0xd5384100 | reg); j then advances to the
            // first instruction of the window that follows.
            if insn & 0xFFFF_FFE0 == 0xD538_4100 {
                let task_reg = insn & 0x1F;

                let mut tag_a = 0u32;
                let mut tag_b = 0u32;
                for k in 1..8 {
                    let pos = match j.checked_add(k * 4) {
                        Some(pos) if pos + 4 <= section.len() => pos,
                        _ => break,
                    };
                    let next_insn = u32::from_le_bytes(section[pos..pos + 4].try_into().unwrap());
                    let op = next_insn & 0xFFC0_0000;
                    // strb / ldrb through the same base register
                    if op != 0x3900_0000 && op != 0x3940_0000 {
                        continue;
                    }
                    if ((next_insn >> 5) & 0x1F) != task_reg {
                        continue;
                    }
                    let imm = (next_insn >> 10) & 0xFFF;
                    if imm == 0 || imm > 255 {
                        continue;
                    }
                    if tag_a == 0 {
                        tag_a = imm;
                    } else if tag_b == 0 && imm != tag_a {
                        tag_b = imm;
                        break;
                    }
                }
                if tag_a != 0 && tag_b != 0 {
                    return Ok(VrKoProbe {
                        module_path,
                        tag_a_offset: tag_a,
                        tag_b_offset: tag_b,
                    });
                }
            }
            j += 4;
        }
    }
    Err(ExtractError::new(
        "the module carries no recognisable tag code (this vr.ko variant has not been measured)",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(kernel_addr: u32) -> Vec<u8> {
        let mut data = VNDRBOOT_MAGIC.to_vec();
        data.extend_from_slice(&3u32.to_le_bytes()); // header_version
        data.extend_from_slice(&4096u32.to_le_bytes()); // page_size
        data.extend_from_slice(&kernel_addr.to_le_bytes()); // kernel_addr
        data
    }

    #[test]
    fn case_a_arm64_gki_alignment() {
        // Use an example (Helio G81 Ultra): kernel_addr=0x40080000 proves
        // phys_offset=0x40000000 via the text-align pattern.
        let (load, offset) = parse_vendor_boot_header(&header(0x4008_0000)).unwrap();
        assert_eq!(load, 0x4008_0000);
        assert_eq!(offset, Some(0x4000_0000));
    }

    #[test]
    fn mib_aligned_load_does_not_imply_dram_base() {
        // kernel_addr=0x40000000 is consistent with dram_base=0x40000000
        // (Dimensity 6300), but is equally consistent with a kernel loaded
        // some whole number of MiB above a lower, unseen base. The pattern
        // alone cannot distinguish these, so phys_offset must stay unknown.
        let (load, offset) = parse_vendor_boot_header(&header(0x4000_0000)).unwrap();
        assert_eq!(load, 0x4000_0000);
        assert_eq!(offset, None);
    }

    #[test]
    fn mib_aligned_load_above_base_is_not_mistaken_for_it() {
        // Regression for the exact case the reviewer flagged: a kernel
        // loaded at 0x40200000 above a 0x40000000 base is also MiB-aligned
        // and must NOT yield phys_offset=0x40200000.
        let (load, offset) = parse_vendor_boot_header(&header(0x4020_0000)).unwrap();
        assert_eq!(load, 0x4020_0000);
        assert_eq!(offset, None);
    }

    #[test]
    fn unknown_alignment_is_refused_not_guessed() {
        let err = parse_vendor_boot_header(&header(0x4012_3456)).unwrap_err();
        assert!(err.to_string().contains("refusing to guess"));
    }

    #[test]
    fn wrong_magic_is_rejected() {
        let err = parse_vendor_boot_header(b"ANDROID!\x00\x00\x00\x00\x00\x00\x00\x00").unwrap_err();
        assert!(err.to_string().contains("VNDRBOOT"));
    }

    #[test]
    fn old_header_version_is_rejected() {
        let mut data = VNDRBOOT_MAGIC.to_vec();
        data.extend_from_slice(&2u32.to_le_bytes()); // header_version < 3
        data.extend_from_slice(&4096u32.to_le_bytes());
        data.extend_from_slice(&0x4008_0000u32.to_le_bytes());
        let err = parse_vendor_boot_header(&data).unwrap_err();
        assert!(err.to_string().contains("header_version"));
    }

    // ---- probe_vrko: synthetic VNDRBOOT -> LZ4-legacy -> cpio -> vr.ko ----

    fn put_u32(out: &mut Vec<u8>, value: u32) {
        out.extend_from_slice(&value.to_le_bytes());
    }

    fn pad_to(out: &mut Vec<u8>, alignment: usize) {
        while out.len() % alignment != 0 {
            out.push(0);
        }
    }

    fn hex8(value: usize) -> String {
        format!("{value:08x}")
    }

    /// cpio newc entry: 110-byte header + name + align4 + data + align4.
    fn cpio_entry(out: &mut Vec<u8>, name: &str, data: &[u8]) {
        let header = format!(
            "070701{ino}{mode}{uid}{gid}{nlink}{mtime}{filesize}{devmajor}{devminor}{rdevmajor}{rdevminor}{namesize}{check}",
            ino = hex8(0),
            mode = hex8(0x81A4), // regular file 0644
            uid = hex8(0),
            gid = hex8(0),
            nlink = hex8(1),
            mtime = hex8(0),
            filesize = hex8(data.len()),
            devmajor = hex8(0),
            devminor = hex8(0),
            rdevmajor = hex8(0),
            rdevminor = hex8(0),
            namesize = hex8(name.len() + 1), // NUL included
            check = hex8(0),
        );
        out.extend_from_slice(header.as_bytes());
        out.extend_from_slice(name.as_bytes());
        out.push(0);
        pad_to(out, 4);
        out.extend_from_slice(data);
        pad_to(out, 4);
    }

    /// One LZ4-legacy block holding literals only (a valid block sequence
    /// that needs no compressor).
    fn lz4_literal_block(out: &mut Vec<u8>, literals: &[u8]) {
        let total = literals.len();
        let head = total.min(15);
        out.push((head as u8) << 4);
        if head == 15 {
            let mut rest = total - head;
            while rest >= 255 {
                out.push(255);
                rest -= 255;
            }
            out.push(rest as u8);
        }
        out.extend_from_slice(literals);
    }

    fn lz4_legacy_frame(ramdisk: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"\x02\x21\x4c\x18");
        for chunk in ramdisk.chunks(4000) {
            let mut block = Vec::new();
            lz4_literal_block(&mut block, chunk);
            put_u32(&mut out, block.len() as u32);
            out.extend_from_slice(&block);
        }
        put_u32(&mut out, 0);
        out
    }

    /// Minimal ELF64 wrapping one executable section whose bytes we control.
    fn elf_with_section(section: &[u8]) -> Vec<u8> {
        // ELF64 header (64 bytes) + one section header (64 bytes) + data.
        let mut ko = vec![0u8; 0x40];
        ko[0] = 0x7f;
        ko[1] = b'E';
        ko[2] = b'L';
        ko[3] = b'F';
        ko[4] = 2; // ELFCLASS64
        ko[5] = 1; // ELFDATA2LSB
        let e_shoff: u64 = 0x40;
        ko[0x28..0x30].copy_from_slice(&e_shoff.to_le_bytes());
        let e_shentsize: u16 = 64;
        let e_shnum: u16 = 2; // null + exec section
        ko[0x3a..0x3c].copy_from_slice(&e_shentsize.to_le_bytes());
        ko[0x3c..0x3e].copy_from_slice(&e_shnum.to_le_bytes());
        ko.extend_from_slice(&[0u8; 64]); // null section header
        let data_off = 0x40 + 64 + 64;
        let mut sh = vec![0u8; 64];
        let sh_type: u32 = 1; // SHT_PROGBITS
        let sh_flags: u64 = 0x4; // SHF_EXECINSTR
        let sh_offset: u64 = data_off as u64;
        let sh_size: u64 = section.len() as u64;
        sh[4..8].copy_from_slice(&sh_type.to_le_bytes());
        sh[8..16].copy_from_slice(&sh_flags.to_le_bytes());
        sh[0x18..0x20].copy_from_slice(&sh_offset.to_le_bytes());
        sh[0x20..0x28].copy_from_slice(&sh_size.to_le_bytes());
        ko.extend_from_slice(&sh);
        ko.extend_from_slice(section);
        ko
    }

    fn insn(word: u32) -> [u8; 4] {
        word.to_le_bytes()
    }

    /// `mrs x8, sp_el0` then strb/ldrb through x8 with tag immediates.
    fn tag_code(tag_a: u32, tag_b: u32) -> Vec<u8> {
        let mut section = Vec::new();
        section.extend_from_slice(&insn(0xD538_4108)); // mrs x8, sp_el0
        section.extend_from_slice(&insn(0x3900_0100 | tag_a << 10 | 8 << 0 | 8 << 5));
        // (strb w8-ish through [x8, #tag_a]: base reg x8 = bits 5-9)
        section.extend_from_slice(&insn(0x3940_0100 | tag_b << 10 | 8 << 5));
        section.extend_from_slice(&insn(0xD503_201F)); // nop
        section.extend_from_slice(&insn(0xD503_201F)); // nop
        section.extend_from_slice(&insn(0xD503_201F)); // nop
        section.extend_from_slice(&insn(0xD503_201F)); // nop
        section.extend_from_slice(&insn(0xD503_201F)); // nop
        section
    }

    fn vendor_boot_with(ramdisk: &[u8], header_size: u32, page: u32) -> Vec<u8> {
        let mut img = vec![0u8; 2124];
        img[0..8].copy_from_slice(b"VNDRBOOT");
        img[8..12].copy_from_slice(&4u32.to_le_bytes());
        img[12..16].copy_from_slice(&page.to_le_bytes());
        img[16..20].copy_from_slice(&0x4008_0000u32.to_le_bytes()); // kernel_addr
        img[24..28].copy_from_slice(&(ramdisk.len() as u32).to_le_bytes());
        img[2096..2100].copy_from_slice(&header_size.to_le_bytes());
        let ramdisk_start = (header_size as usize).div_ceil(page as usize) * page as usize;
        img.resize(ramdisk_start.max(2124), 0);
        img.extend_from_slice(ramdisk);
        img
    }

    fn full_image(tag_a: u32, tag_b: u32) -> Vec<u8> {
        let ko = elf_with_section(&tag_code(tag_a, tag_b));
        let mut cpio = Vec::new();
        cpio_entry(&mut cpio, "lib/modules/6.1.145-android14/vr.ko", &ko);
        cpio_entry(&mut cpio, "TRAILER!!!", b"");
        let lz4 = lz4_legacy_frame(&cpio);
        vendor_boot_with(&lz4, 2124, 4096)
    }

    #[test]
    fn probe_recovers_tag_a_and_tag_b() {
        // The measured families: tag A = 0x06 (6.6/6.12) / tag B = 0x2c.
        let img = full_image(0x06, 0x2c);
        let probe = probe_vrko(&img).unwrap();
        assert_eq!(probe.tag_a_offset, 0x06);
        assert_eq!(probe.tag_b_offset, 0x2c);
        assert_eq!(probe.module_path, "lib/modules/6.1.145-android14/vr.ko");

        // And the 6.1 shape (both within the 8-instruction window).
        let img = full_image(0x2a, 0x44);
        let probe = probe_vrko(&img).unwrap();
        assert_eq!(probe.tag_a_offset, 0x2a);
        assert_eq!(probe.tag_b_offset, 0x44);
    }

    #[test]
    fn probe_rejects_non_vndrboot() {
        let err = probe_vrko(&[0u8; 4096]).unwrap_err();
        assert!(err.to_string().contains("VNDRBOOT"));
    }

    #[test]
    fn probe_rejects_elf_without_tag_code() {
        let ko = elf_with_section(&[0x1f, 0x20, 0x03, 0xd5].repeat(8));
        let mut cpio = Vec::new();
        cpio_entry(&mut cpio, "lib/modules/vr.ko", &ko);
        cpio_entry(&mut cpio, "TRAILER!!!", b"");
        let img = vendor_boot_with(&lz4_legacy_frame(&cpio), 2124, 4096);
        let err = probe_vrko(&img).unwrap_err();
        assert!(err.to_string().contains("no recognisable tag code"));
    }

    #[test]
    fn probe_rejects_ramdisk_without_vr_ko() {
        let mut cpio = Vec::new();
        cpio_entry(&mut cpio, "lib/modules/other.ko", &[0u8; 128]);
        cpio_entry(&mut cpio, "TRAILER!!!", b"");
        let img = vendor_boot_with(&lz4_legacy_frame(&cpio), 2124, 4096);
        let err = probe_vrko(&img).unwrap_err();
        assert!(err.to_string().contains("no lib/modules/vr.ko"));
    }

    #[test]
    fn probe_rejects_truncated_ramdisk_declaration() {
        let ko = elf_with_section(&tag_code(6, 0x2c));
        let mut cpio = Vec::new();
        cpio_entry(&mut cpio, "lib/modules/vr.ko", &ko);
        cpio_entry(&mut cpio, "TRAILER!!!", b"");
        let mut lz4 = lz4_legacy_frame(&cpio);
        // declare far more than the image carries
        let mut img = vec![0u8; 2124];
        img[0..8].copy_from_slice(b"VNDRBOOT");
        img[8..12].copy_from_slice(&4u32.to_le_bytes());
        img[12..16].copy_from_slice(&4096u32.to_le_bytes());
        img[24..28].copy_from_slice(&((lz4.len() as u32) * 100).to_le_bytes());
        img[2096..2100].copy_from_slice(&2124u32.to_le_bytes());
        img.extend_from_slice(&mut lz4);
        let err = probe_vrko(&img).unwrap_err();
        assert!(err.to_string().contains("past the end of the file"));
    }
}
