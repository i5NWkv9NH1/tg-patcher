// * 二进制处理模块：Mach-O 尾部 LC_LOAD_DYLIB 注入、ARM64 交叉引用扫描与去广告特征验证
use std::fs;
use std::path::Path;
use tracing::{debug, error, warn};

pub const MH_MAGIC_64: u32 = 0xfeedfacf;
pub const MH_CIGAM_64: u32 = 0xcffaedfe;
pub const FAT_MAGIC: u32 = 0xcafebabe;
pub const FAT_CIGAM: u32 = 0xbebafeca;
pub const CPU_TYPE_ARM64: u32 = 0x0100000c;
pub const LC_LOAD_DYLIB: u32 = 0x0000000c;
pub const LC_SEGMENT_64: u32 = 0x00000019;
pub const LC_FUNCTION_STARTS: u32 = 0x00000026;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InjectResult {
    Injected,
    AlreadyPresent,
    FixedAndInjected,
}

#[derive(Debug, Clone)]
pub struct Arm64XrefMatch {
    pub needle: String,
    pub string_va: u64,
    pub xref_insn_va: u64,
    pub func_start_va: Option<u64>,
    pub prologue_insns: [u32; 4],
}

#[derive(Debug, Clone)]
pub struct AdBlockSpotReport {
    pub name: &'static str,
    pub matched_vas: Vec<u64>,
}

#[derive(Debug, thiserror::Error)]
pub enum MachoError {
    #[error("文件 I/O 异常: {0}")]
    Io(#[from] std::io::Error),
    #[error("不支持的二进制格式 (魔数: 0x{0:x})")]
    UnsupportedMagic(u32),
    #[error("未在通用二进制中找到 arm64 架构切片")]
    Arm64SliceNotFound,
    #[error("Mach-O 头部或加载命令损坏: {0}")]
    Corrupted(String),
    #[error("二进制头部空闲填充空间不足，无法追加加载命令")]
    NoSpaceAvailable,
    #[error("Mach-O 头部预留填充区包含非零数据，为保护后续代码段已终止写入")]
    HeaderPaddingNotZero,
}

pub fn find_arm64_slice_range(data: &[u8]) -> Result<(usize, usize), MachoError> {
    if data.len() < 4 {
        return Err(MachoError::Corrupted("文件长度小于 4 字节".to_string()));
    }
    let magic = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
    if magic == FAT_MAGIC || magic == FAT_CIGAM {
        debug!("检测到 Universal 通用二进制 (FAT 容器)");
        if data.len() < 8 {
            return Err(MachoError::Corrupted("FAT 头部长度不足".to_string()));
        }
        let nfat_arch = u32::from_be_bytes([data[4], data[5], data[6], data[7]]) as usize;
        if nfat_arch == 0 || nfat_arch > 8 {
            return Err(MachoError::Corrupted(format!(
                "FAT 架构数量异常 ({nfat_arch})"
            )));
        }
        let mut offset = 8;
        for _ in 0..nfat_arch {
            if offset + 20 > data.len() {
                return Err(MachoError::Corrupted("FAT 架构描述表截断".to_string()));
            }
            let cputype = u32::from_be_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            let slice_offset = u32::from_be_bytes([
                data[offset + 8],
                data[offset + 9],
                data[offset + 10],
                data[offset + 11],
            ]) as usize;
            let slice_size = u32::from_be_bytes([
                data[offset + 12],
                data[offset + 13],
                data[offset + 14],
                data[offset + 15],
            ]) as usize;
            if cputype == CPU_TYPE_ARM64 {
                if slice_offset + slice_size > data.len() {
                    return Err(MachoError::Corrupted("arm64 切片范围越界".to_string()));
                }
                return Ok((slice_offset, slice_size));
            }
            offset += 20;
        }
        Err(MachoError::Arm64SliceNotFound)
    } else if magic == MH_MAGIC_64 || magic == MH_CIGAM_64 {
        Ok((0, data.len()))
    } else {
        error!("未知或不支持的二进制魔数: 0x{magic:x}");
        Err(MachoError::UnsupportedMagic(magic))
    }
}

pub fn find_arm64_slice_offset(data: &[u8]) -> Result<usize, MachoError> {
    find_arm64_slice_range(data).map(|(off, _)| off)
}

pub fn inject_slice(
    data: &mut [u8],
    slice_offset: usize,
    dylib_path: &str,
) -> Result<InjectResult, MachoError> {
    if data.len() < slice_offset + 32 {
        return Err(MachoError::Corrupted(
            "切片数据小于 mach_header_64 尺寸".to_string(),
        ));
    }
    let magic = u32::from_le_bytes([
        data[slice_offset],
        data[slice_offset + 1],
        data[slice_offset + 2],
        data[slice_offset + 3],
    ]);
    if magic != MH_MAGIC_64 {
        return Err(MachoError::Corrupted(format!(
            "切片魔数非 MH_MAGIC_64: 0x{magic:x}"
        )));
    }
    let mut ncmds = u32::from_le_bytes([
        data[slice_offset + 16],
        data[slice_offset + 17],
        data[slice_offset + 18],
        data[slice_offset + 19],
    ]);
    let mut sizeofcmds = u32::from_le_bytes([
        data[slice_offset + 20],
        data[slice_offset + 21],
        data[slice_offset + 22],
        data[slice_offset + 23],
    ]);
    let cmds_start = slice_offset + 32;
    let mut cmds_end = cmds_start + sizeofcmds as usize;
    if data.len() < cmds_end {
        return Err(MachoError::Corrupted(
            "加载命令总长度超出切片边界".to_string(),
        ));
    }
    let path_bytes = dylib_path.as_bytes();
    let path_len_with_null = path_bytes.len() + 1;
    let add_cmdsize = ((24 + path_len_with_null + 7) & !7) as u32;
    let mut cursor = cmds_start;
    let mut fixed_misplaced = false;
    let mut i = 0;
    while i < ncmds {
        if cursor + 8 > cmds_end {
            return Err(MachoError::Corrupted("遍历加载命令时发生越界".to_string()));
        }
        let cmd = u32::from_le_bytes([
            data[cursor],
            data[cursor + 1],
            data[cursor + 2],
            data[cursor + 3],
        ]);
        let cmdsize = u32::from_le_bytes([
            data[cursor + 4],
            data[cursor + 5],
            data[cursor + 6],
            data[cursor + 7],
        ]) as usize;
        if cmdsize < 8 || cursor + cmdsize > cmds_end {
            return Err(MachoError::Corrupted(format!(
                "加载命令尺寸异常: cmd=0x{cmd:x}, size={cmdsize}"
            )));
        }
        if cmd == LC_LOAD_DYLIB && cmdsize >= 24 {
            let name_offset = u32::from_le_bytes([
                data[cursor + 8],
                data[cursor + 9],
                data[cursor + 10],
                data[cursor + 11],
            ]) as usize;
            if name_offset < cmdsize && cursor + name_offset < cmds_end {
                let str_bytes = &data[cursor + name_offset..cursor + cmdsize];
                let parsed_name =
                    std::str::from_utf8(str_bytes.split(|&b| b == 0).next().unwrap_or_default())
                        .unwrap_or_default();
                if parsed_name == dylib_path {
                    if i == ncmds - 1 {
                        debug!("补丁已存在于加载表最末尾，无需重复写入");
                        return Ok(InjectResult::AlreadyPresent);
                    }
                    warn!("检测到错位项，正在剔除并重排加载命令表...");
                    let copy_src = cursor + cmdsize;
                    let copy_len = cmds_end - copy_src;
                    data.copy_within(copy_src..copy_src + copy_len, cursor);
                    ncmds -= 1;
                    sizeofcmds -= cmdsize as u32;
                    cmds_end -= cmdsize;
                    data[cmds_end..cmds_end + cmdsize].fill(0);
                    fixed_misplaced = true;
                    continue;
                }
            }
        }
        cursor += cmdsize;
        i += 1;
    }
    if data.len() < cmds_end + add_cmdsize as usize {
        return Err(MachoError::NoSpaceAvailable);
    }
    let target_range = cmds_end..cmds_end + add_cmdsize as usize;
    if data[target_range.clone()].iter().any(|&b| b != 0) {
        error!("Mach-O 头部预留填充区包含非零数据，为保护后续代码段已终止写入");
        return Err(MachoError::HeaderPaddingNotZero);
    }
    let mut new_cmd = vec![0u8; add_cmdsize as usize];
    new_cmd[0..4].copy_from_slice(&LC_LOAD_DYLIB.to_le_bytes());
    new_cmd[4..8].copy_from_slice(&add_cmdsize.to_le_bytes());
    new_cmd[8..12].copy_from_slice(&24u32.to_le_bytes());
    new_cmd[12..16].copy_from_slice(&2u32.to_le_bytes());
    new_cmd[16..20].copy_from_slice(&0x00010000u32.to_le_bytes());
    new_cmd[20..24].copy_from_slice(&0x00010000u32.to_le_bytes());
    new_cmd[24..24 + path_bytes.len()].copy_from_slice(path_bytes);
    new_cmd[24 + path_bytes.len()] = 0;
    data[target_range].copy_from_slice(&new_cmd);
    ncmds += 1;
    sizeofcmds += add_cmdsize;
    data[slice_offset + 16..slice_offset + 20].copy_from_slice(&ncmds.to_le_bytes());
    data[slice_offset + 20..slice_offset + 24].copy_from_slice(&sizeofcmds.to_le_bytes());
    if fixed_misplaced {
        Ok(InjectResult::FixedAndInjected)
    } else {
        Ok(InjectResult::Injected)
    }
}

pub fn inject_file<P: AsRef<Path>>(path: P, dylib_path: &str) -> Result<InjectResult, MachoError> {
    let path_ref = path.as_ref();
    let mut data = fs::read(path_ref)?;
    let slice_offset = find_arm64_slice_offset(&data)?;
    let result = inject_slice(&mut data, slice_offset, dylib_path)?;
    if result != InjectResult::AlreadyPresent {
        fs::write(path_ref, &data)?;
    }
    Ok(result)
}

struct TextLayout {
    text_vmaddr: u64,
    text_fileoff: usize,
    text_filesize: usize,
    code_sec_offset: usize,
    code_sec_size: usize,
    func_starts_off: usize,
    func_starts_size: usize,
}

fn parse_text_layout(slice: &[u8]) -> Result<TextLayout, MachoError> {
    if slice.len() < 32 {
        return Err(MachoError::Corrupted("arm64 切片长度不足".to_string()));
    }
    let ncmds = u32::from_le_bytes([slice[16], slice[17], slice[18], slice[19]]) as usize;
    let sizeofcmds = u32::from_le_bytes([slice[20], slice[21], slice[22], slice[23]]) as usize;
    let mut layout = TextLayout {
        text_vmaddr: 0x100000000,
        text_fileoff: 0,
        text_filesize: 0,
        code_sec_offset: 0,
        code_sec_size: 0,
        func_starts_off: 0,
        func_starts_size: 0,
    };
    let mut cursor = 32;
    let cmds_end = (32 + sizeofcmds).min(slice.len());
    for _ in 0..ncmds {
        if cursor + 8 > cmds_end {
            break;
        }
        let cmd = u32::from_le_bytes([
            slice[cursor],
            slice[cursor + 1],
            slice[cursor + 2],
            slice[cursor + 3],
        ]);
        let cmdsize = u32::from_le_bytes([
            slice[cursor + 4],
            slice[cursor + 5],
            slice[cursor + 6],
            slice[cursor + 7],
        ]) as usize;
        if cmdsize < 8 || cursor + cmdsize > cmds_end {
            break;
        }
        if cmd == LC_SEGMENT_64 && cmdsize >= 72 {
            let segname = &slice[cursor + 8..cursor + 24];
            if segname.starts_with(b"__TEXT\0") {
                layout.text_vmaddr =
                    u64::from_le_bytes(slice[cursor + 24..cursor + 32].try_into().unwrap());
                layout.text_fileoff =
                    u64::from_le_bytes(slice[cursor + 40..cursor + 48].try_into().unwrap())
                        as usize;
                layout.text_filesize =
                    u64::from_le_bytes(slice[cursor + 48..cursor + 56].try_into().unwrap())
                        as usize;
                let nsects = u32::from_le_bytes(slice[cursor + 64..cursor + 68].try_into().unwrap())
                    as usize;
                let mut sec_cursor = cursor + 72;
                for _ in 0..nsects {
                    if sec_cursor + 80 > cursor + cmdsize {
                        break;
                    }
                    let sectname = &slice[sec_cursor..sec_cursor + 16];
                    if sectname.starts_with(b"__text\0") {
                        layout.code_sec_size = u64::from_le_bytes(
                            slice[sec_cursor + 40..sec_cursor + 48].try_into().unwrap(),
                        ) as usize;
                        layout.code_sec_offset = u32::from_le_bytes(
                            slice[sec_cursor + 48..sec_cursor + 52].try_into().unwrap(),
                        ) as usize;
                    }
                    sec_cursor += 80;
                }
            }
        } else if cmd == LC_FUNCTION_STARTS && cmdsize >= 16 {
            layout.func_starts_off =
                u32::from_le_bytes(slice[cursor + 8..cursor + 12].try_into().unwrap()) as usize;
            layout.func_starts_size =
                u32::from_le_bytes(slice[cursor + 12..cursor + 16].try_into().unwrap()) as usize;
        }
        cursor += cmdsize;
    }
    Ok(layout)
}

// * 离线验证 3 处去广告指令特征码在当前 Telegram 版本中的命中情况
pub fn verify_adblock_signatures(file_data: &[u8]) -> Result<Vec<AdBlockSpotReport>, MachoError> {
    let (slice_off, slice_len) = find_arm64_slice_range(file_data)?;
    let slice = &file_data[slice_off..slice_off + slice_len];
    let layout = parse_text_layout(slice)?;
    let mut reports = vec![
        AdBlockSpotReport {
            name: "关卡1: 本地5分钟缓存广告分支 (b.le -> NOP)",
            matched_vas: Vec::new(),
        },
        AdBlockSpotReport {
            name: "关卡2: 广告数组长度读取 (ldr x27 -> mov x27, #0)",
            matched_vas: Vec::new(),
        },
        AdBlockSpotReport {
            name: "关卡3: 网络拉取广告激活分支 (tbz -> NOP)",
            matched_vas: Vec::new(),
        },
    ];
    if layout.code_sec_offset == 0 || layout.code_sec_offset + layout.code_sec_size > slice.len() {
        return Ok(reports);
    }
    let code_bytes = &slice[layout.code_sec_offset..layout.code_sec_offset + layout.code_sec_size];
    let code_base_va =
        layout.text_vmaddr + (layout.code_sec_offset.saturating_sub(layout.text_fileoff)) as u64;
    let words: Vec<u32> = code_bytes
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect();

    for (idx, w) in words.windows(5).enumerate() {
        if w[0] == 0x1e780108 && w[1] == 0x7104b108 && w[3] == 0x6b1b011f {
            reports[0]
                .matched_vas
                .push(code_base_va + ((idx + 4) * 4) as u64);
        }
    }
    for (idx, w) in words.windows(3).enumerate() {
        if w[0] == 0xf9400a7b && w[1] == 0xd2800015 && w[2] == 0x92420b1c {
            reports[1].matched_vas.push(code_base_va + (idx * 4) as u64);
        }
        if w[0] == 0x39420288 && (w[1] & 0xff00001f) == 0x36000008 && w[2] == 0xa9487bfd {
            reports[2]
                .matched_vas
                .push(code_base_va + ((idx + 1) * 4) as u64);
        }
    }
    Ok(reports)
}

// * 解析 __TEXT 段与 LC_FUNCTION_STARTS 表，对特征字符串执行 ARM64 ADRP+ADD 交叉引用扫描
pub fn scan_arm64_string_xrefs(
    file_data: &[u8],
    needles: &[&str],
) -> Result<Vec<Arm64XrefMatch>, MachoError> {
    let (slice_off, slice_len) = find_arm64_slice_range(file_data)?;
    let slice = &file_data[slice_off..slice_off + slice_len];
    let layout = parse_text_layout(slice)?;

    let mut function_starts = Vec::new();
    if layout.func_starts_off > 0 && layout.func_starts_off + layout.func_starts_size <= slice.len()
    {
        let mut addr = layout.text_vmaddr;
        let mut idx = layout.func_starts_off;
        let end = layout.func_starts_off + layout.func_starts_size;
        while idx < end {
            let mut delta: u64 = 0;
            let mut shift = 0;
            loop {
                if idx >= end {
                    break;
                }
                let byte = slice[idx];
                idx += 1;
                delta |= ((byte & 0x7f) as u64) << shift;
                if (byte & 0x80) == 0 {
                    break;
                }
                shift += 7;
            }
            if delta == 0 {
                break;
            }
            addr += delta;
            function_starts.push(addr);
        }
    }

    // * 仅在 __TEXT 段范围内检索字符串，确保虚拟地址换算准确
    let text_end = (layout.text_fileoff + layout.text_filesize).min(slice.len());
    let text_slice = &slice[layout.text_fileoff..text_end];
    let mut targets: std::collections::HashMap<u64, &str> = std::collections::HashMap::new();
    for &needle in needles {
        let nb = needle.as_bytes();
        if nb.is_empty() || text_slice.len() < nb.len() {
            continue;
        }
        let mut search_from = 0;
        while let Some(rel_pos) = text_slice[search_from..]
            .windows(nb.len())
            .position(|w| w == nb)
        {
            let pos = search_from + rel_pos;
            let mut cstr_start = pos;
            while cstr_start > 0 && text_slice[cstr_start - 1] != 0 && (pos - cstr_start) < 256 {
                cstr_start -= 1;
            }
            let exact_va = layout.text_vmaddr + pos as u64;
            let start_va = layout.text_vmaddr + cstr_start as u64;
            targets.insert(exact_va, needle);
            targets.insert(start_va, needle);
            search_from = pos + nb.len();
        }
    }

    let mut results = Vec::new();
    if layout.code_sec_offset == 0
        || layout.code_sec_offset + layout.code_sec_size > slice.len()
        || targets.is_empty()
    {
        return Ok(results);
    }
    let code_bytes = &slice[layout.code_sec_offset..layout.code_sec_offset + layout.code_sec_size];
    let code_base_va =
        layout.text_vmaddr + (layout.code_sec_offset.saturating_sub(layout.text_fileoff)) as u64;

    let mut adrp_regs: [(u64, u64); 32] = [(0, 0); 32];
    let insn_count = code_bytes.len() / 4;
    for i in 0..insn_count {
        let insn = u32::from_le_bytes(code_bytes[i * 4..i * 4 + 4].try_into().unwrap());
        let pc = code_base_va + (i as u64) * 4;

        // * 遇到函数调用 BL / BLR 时清空调用者保存寄存器 x0..=x18，减少误报
        if (insn & 0xFC000000) == 0x94000000 || (insn & 0xFFFFFC1F) == 0xD63F0000 {
            for slot in adrp_regs.iter_mut().take(19) {
                *slot = (0, 0);
            }
            continue;
        }

        // * ADRP Xd, page
        if (insn & 0x9F000000) == 0x90000000 {
            let rd = (insn & 0x1F) as usize;
            let immlo = (insn >> 29) & 0x3;
            let immhi = (insn >> 5) & 0x7FFFF;
            let raw_imm21 = (immhi << 2) | immlo;
            let signed_imm21 = ((raw_imm21 as i32) << 11) >> 11;
            let page_offset = (signed_imm21 as i64) << 12;
            let target_page = ((pc & !0xFFF) as i64 + page_offset) as u64;
            adrp_regs[rd] = (target_page, pc);
            continue;
        }

        // * 64位 ADD Xd, Xn, #imm12
        if (insn & 0xFFC00000) == 0x91000000 {
            let rn = ((insn >> 5) & 0x1F) as usize;
            let rd = (insn & 0x1F) as usize;
            let imm12 = ((insn >> 10) & 0xFFF) as u64;
            let (page_va, adrp_pc) = adrp_regs[rn];
            if page_va != 0 && pc.saturating_sub(adrp_pc) <= 64 {
                let resolved_va = page_va + imm12;
                if let Some(&needle) = targets.get(&resolved_va) {
                    let func_start = match function_starts.binary_search(&adrp_pc) {
                        Ok(exact_idx) => Some(function_starts[exact_idx]),
                        Err(insert_idx) if insert_idx > 0 => Some(function_starts[insert_idx - 1]),
                        _ => None,
                    };
                    let mut prologue = [0u32; 4];
                    if let Some(f_va) = func_start
                        && f_va >= code_base_va
                    {
                        let f_off = (f_va - code_base_va) as usize;
                        if f_off + 16 <= code_bytes.len() {
                            for (k, slot) in prologue.iter_mut().enumerate() {
                                *slot = u32::from_le_bytes(
                                    code_bytes[f_off + k * 4..f_off + k * 4 + 4]
                                        .try_into()
                                        .unwrap(),
                                );
                            }
                        }
                    }
                    results.push(Arm64XrefMatch {
                        needle: needle.to_string(),
                        string_va: resolved_va,
                        xref_insn_va: adrp_pc,
                        func_start_va: func_start,
                        prologue_insns: prologue,
                    });
                }
            }
            if rd != rn {
                adrp_regs[rd] = (0, 0);
            }
        }
    }
    Ok(results)
}
