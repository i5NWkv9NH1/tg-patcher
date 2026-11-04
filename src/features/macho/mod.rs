// * 二进制处理切片：负责 Mach-O 尾部 LC_LOAD_DYLIB 注入与 ARM64 机器码交叉引用分析

use std::fs;
use std::path::Path;
use tracing::{debug, error, warn};

// * Mach-O 与 FAT 核心魔数与常量定义
pub const MH_MAGIC_64: u32 = 0xfeedfacf;
pub const MH_CIGAM_64: u32 = 0xcffaedfe;
pub const FAT_MAGIC: u32 = 0xcafebabe;
pub const FAT_CIGAM: u32 = 0xbebafeca;
pub const CPU_TYPE_ARM64: u32 = 0x0100000c;
pub const LC_LOAD_DYLIB: u32 = 0x0000000c;
pub const LC_SEGMENT_64: u32 = 0x00000019;
pub const LC_FUNCTION_STARTS: u32 = 0x00000026;

// * 注入执行结果枚举
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InjectResult {
    // * 动态库已成功追加写入加载表末尾
    Injected,
    // * 动态库已在加载表末尾，无需重复操作
    AlreadyPresent,
    // * 修复了不在末尾的错位项，并重新追加至末尾
    FixedAndInjected,
}

// * ARM64 字符串交叉引用探测结果
#[derive(Debug, Clone)]
pub struct Arm64XrefMatch {
    pub needle: String,
    pub string_va: u64,
    pub xref_insn_va: u64,
    pub func_start_va: Option<u64>,
    pub prologue_insns: [u32; 4],
}

// * Mach-O 操作异常枚举
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

// * 解析 Mach-O 头部以获取 arm64 切片的起始偏移与长度
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
        // ! 校验架构数量在 1..=8 之间，避免与同样使用 0xCAFEBABE 的 Java class 文件冲突
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

// * 兼容仅需起始偏移量的调用方
pub fn find_arm64_slice_offset(data: &[u8]) -> Result<usize, MachoError> {
    find_arm64_slice_range(data).map(|(off, _)| off)
}

// * 在指定的 Mach-O 字节流中对 arm64 切片注入 LC_LOAD_DYLIB
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

    // ! 检查即将写入的预留填充区是否全为 0，防止覆盖后续代码段
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

// * 对指定二进制文件执行加载表注入
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

// * 解析 Mach-O 的 __TEXT 段信息与 LC_FUNCTION_STARTS 表，对指定特征字符串执行 ARM64 ADRP+ADD 交叉引用扫描
pub fn scan_arm64_string_xrefs(
    file_data: &[u8],
    needles: &[&str],
) -> Result<Vec<Arm64XrefMatch>, MachoError> {
    let (slice_off, slice_len) = find_arm64_slice_range(file_data)?;
    let slice = &file_data[slice_off..slice_off + slice_len];

    if slice.len() < 32 {
        return Err(MachoError::Corrupted("arm64 切片长度不足".to_string()));
    }

    let ncmds = u32::from_le_bytes([slice[16], slice[17], slice[18], slice[19]]) as usize;
    let sizeofcmds = u32::from_le_bytes([slice[20], slice[21], slice[22], slice[23]]) as usize;

    let mut text_vmaddr: u64 = 0x100000000;
    let mut text_fileoff: usize = 0;
    let mut code_sec_offset: usize = 0;
    let mut code_sec_size: usize = 0;
    let mut func_starts_off: usize = 0;
    let mut func_starts_size: usize = 0;

    let mut cursor = 32;
    let cmds_end = (32 + sizeofcmds).min(slice.len());

    // * 1. 遍历加载命令，提取 __TEXT 段基址、__text 代码节范围以及 LC_FUNCTION_STARTS 表
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
                text_vmaddr =
                    u64::from_le_bytes(slice[cursor + 24..cursor + 32].try_into().unwrap());
                text_fileoff =
                    u64::from_le_bytes(slice[cursor + 40..cursor + 48].try_into().unwrap())
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
                        code_sec_size = u64::from_le_bytes(
                            slice[sec_cursor + 40..sec_cursor + 48].try_into().unwrap(),
                        ) as usize;
                        code_sec_offset = u32::from_le_bytes(
                            slice[sec_cursor + 48..sec_cursor + 52].try_into().unwrap(),
                        ) as usize;
                    }
                    sec_cursor += 80;
                }
            }
        } else if cmd == LC_FUNCTION_STARTS && cmdsize >= 16 {
            func_starts_off =
                u32::from_le_bytes(slice[cursor + 8..cursor + 12].try_into().unwrap()) as usize;
            func_starts_size =
                u32::from_le_bytes(slice[cursor + 12..cursor + 16].try_into().unwrap()) as usize;
        }

        cursor += cmdsize;
    }

    // * 2. 解码 ULEB128 格式的 LC_FUNCTION_STARTS，拿到所有被 Strip 函数的精确入口虚拟地址
    let mut function_starts = Vec::new();
    if func_starts_off > 0 && func_starts_off + func_starts_size <= slice.len() {
        let mut addr = text_vmaddr;
        let mut idx = func_starts_off;
        let end = func_starts_off + func_starts_size;
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

    // * 3. 搜索目标字符串在切片内的文件偏移并换算为虚拟地址 (VA)
    let mut targets: Vec<(&str, u64)> = Vec::new();
    for &needle in needles {
        let nb = needle.as_bytes();
        if let Some(pos) = slice.windows(nb.len()).position(|w| w == nb) {
            // ! 确保匹配的是完整字符串或后缀锚点
            let va = text_vmaddr + (pos.saturating_sub(text_fileoff)) as u64;
            targets.push((needle, va));
        }
    }

    let mut results = Vec::new();
    if code_sec_offset == 0 || code_sec_offset + code_sec_size > slice.len() || targets.is_empty() {
        return Ok(results);
    }

    let code_bytes = &slice[code_sec_offset..code_sec_offset + code_sec_size];
    let code_base_va = text_vmaddr + (code_sec_offset.saturating_sub(text_fileoff)) as u64;

    // * 4. 扫描 __TEXT,__text 全部 ARM64 指令对 (ADRP Xd, page + ADD Xd, Xd, #off12)
    let insn_count = code_bytes.len() / 4;
    for i in 0..insn_count.saturating_sub(1) {
        let insn1 = u32::from_le_bytes(code_bytes[i * 4..i * 4 + 4].try_into().unwrap());
        // ! 判断是否为 ADRP 指令: (insn & 0x9F000000) == 0x90000000
        if (insn1 & 0x9F000000) != 0x90000000 {
            continue;
        }

        let rd1 = insn1 & 0x1F;
        let immlo = (insn1 >> 29) & 0x3;
        let immhi = (insn1 >> 5) & 0x7FFFF;
        let raw_imm21 = (immhi << 2) | immlo;
        // * 21 位有符号页偏移扩展为 i64 并左移 12 位
        let signed_imm21 = ((raw_imm21 as i32) << 11) >> 11;
        let page_offset = (signed_imm21 as i64) << 12;

        let pc = code_base_va + (i as u64) * 4;
        let target_page = ((pc & !0xFFF) as i64 + page_offset) as u64;

        // * 检查紧随其后的 1~2 条指令是否为 ADD Xd, Xd, #imm12
        for lookahead in 1..=2 {
            if i + lookahead >= insn_count {
                break;
            }
            let insn2 = u32::from_le_bytes(
                code_bytes[(i + lookahead) * 4..(i + lookahead) * 4 + 4]
                    .try_into()
                    .unwrap(),
            );
            // ! 64位 ADD (immediate, shift=0): (insn2 & 0xFFC00000) == 0x91000000
            if (insn2 & 0xFFC00000) != 0x91000000 {
                continue;
            }
            let rn2 = (insn2 >> 5) & 0x1F;
            if rn2 != rd1 {
                continue;
            }
            let imm12 = ((insn2 >> 10) & 0xFFF) as u64;
            let resolved_va = target_page + imm12;

            for &(needle, str_va) in &targets {
                if resolved_va == str_va {
                    // * 二分查找包含当前指令的所属函数起始地址
                    let func_start = match function_starts.binary_search(&pc) {
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
                        string_va: str_va,
                        xref_insn_va: pc,
                        func_start_va: func_start,
                        prologue_insns: prologue,
                    });
                }
            }
        }
    }

    Ok(results)
}
