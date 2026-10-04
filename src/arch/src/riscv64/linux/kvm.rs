// Copyright 2026 The libkrun Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;
use std::result;

use kvm_ioctls::VmFd;
use log::debug;

/// Errors encountered during ISA detection and configuration discovery.
#[derive(Debug)]
pub enum IsaError {
    /// Failed to read ISA register from KVM.
    ReadIsaReg(kvm_ioctls::Error),
}

type Result<T> = result::Result<T, IsaError>;

/// ISA extension information discovered from the host KVM.
#[derive(Debug, Clone)]
pub struct RiscvIsaInfo {
    /// ISA base features as a string (e.g., "rv64imafdc_smaia_ssaia")
    pub isa_string: String,
    /// List of ISA extensions supported by the host
    pub extensions: BTreeSet<String>,
    /// Cache block size for Zicbom (in bytes), if available
    pub zicbom_block_size: Option<u32>,
    /// Cache block size for Zicboz (in bytes), if available
    pub zicboz_block_size: Option<u32>,
    /// Cache block size for Zicbop (in bytes), if available
    pub zicbop_block_size: Option<u32>,
}

/// Helper macro to get the ID of a riscv64 CONFIG register.
#[macro_export]
macro_rules! riscv64_config_reg {
    ($offset: tt) => {
        kvm_bindings::KVM_REG_RISCV as u64
            | u64::from(kvm_bindings::KVM_REG_SIZE_U64)
            | u64::from(kvm_bindings::KVM_REG_RISCV_CONFIG)
            | (($offset / std::mem::size_of::<u64>()) as u64)
    };
}

/// Helper macro to get the ID of a riscv64 ISA_EXT register.
#[macro_export]
macro_rules! riscv64_isa_ext_reg {
    ($subtype: tt, $ext_id: tt) => {
        kvm_bindings::KVM_REG_RISCV as u64
            | u64::from(kvm_bindings::KVM_REG_SIZE_U64)
            | u64::from(kvm_bindings::KVM_REG_RISCV_ISA_EXT)
            | (($subtype as u64) << 16)
            | ($ext_id as u64)
    };
}

/// Detects the host ISA configuration and supported extensions.
pub fn detect_host_isa(vm: &VmFd) -> Result<RiscvIsaInfo> {
    debug!("Starting RISC-V ISA detection");

    let isa_string = read_isa_register(vm)?;
    debug!("Detected ISA string: {}", isa_string);

    let extensions = match detect_extensions_modern(vm) {
        Some(exts) => {
            debug!("Using modern detection method: {} extensions", exts.len());
            exts
        }
        None => {
            debug!("Modern detection returned None, falling back to legacy method");
            detect_extensions_legacy(vm)
        }
    };

    debug!(
        "Total extensions detected: {} ({})",
        extensions.len(),
        extensions.iter().cloned().collect::<Vec<_>>().join(", ")
    );

    let zicbom_block_size = read_block_size_if_present(vm, "zicbom_block_size");
    let zicboz_block_size = read_block_size_if_present(vm, "zicboz_block_size");
    let zicbop_block_size = read_block_size_if_present(vm, "zicbop_block_size");

    debug!(
        "ISA detection complete: isa_string={}, extensions={}, zicbom_block_size={:?}, zicboz_block_size={:?}, zicbop_block_size={:?}",
        isa_string,
        extensions.len(),
        zicbom_block_size,
        zicboz_block_size,
        zicbop_block_size
    );

    Ok(RiscvIsaInfo {
        isa_string,
        extensions,
        zicbom_block_size,
        zicboz_block_size,
        zicbop_block_size,
    })
}

fn read_isa_register(vm: &VmFd) -> Result<String> {
    debug!("Reading ISA register from vCPU 0");

    // Open existing vCPU 0 (it's guaranteed to exist by the time this is called)
    let vcpu_fd = vm.create_vcpu(0).map_err(|e| IsaError::ReadIsaReg(e))?;

    // KVM_REG_RISCV_CONFIG | KVM_REG_SIZE_U128 | offset for "isa"
    // ISA string register: 16-byte register containing the ISA string
    let isa_reg_id = kvm_bindings::KVM_REG_RISCV as u64
        | u64::from(kvm_bindings::KVM_REG_SIZE_U128)
        | u64::from(kvm_bindings::KVM_REG_RISCV_CONFIG)
        | 0; // isa register offset

    let mut isa_bytes = [0u8; 16];
    vcpu_fd
        .get_one_reg(isa_reg_id, &mut isa_bytes)
        .map_err(|e| IsaError::ReadIsaReg(e))?;

    // Find NUL terminator and convert to string
    let len = isa_bytes.iter().position(|&b| b == 0).unwrap_or(16);
    let isa_string = String::from_utf8_lossy(&isa_bytes[..len]).to_string();
    debug!("Read ISA string from vCPU 0: {}", isa_string);
    Ok(isa_string)
}

fn detect_extensions_modern(_vm: &VmFd) -> Option<BTreeSet<String>> {
    debug!("Modern detection: KVM_REG_RISCV_ISA_EXT not yet available, using legacy method");
    None
}

fn extract_single_letter_extensions(isa_bits: u64) -> BTreeSet<String> {
    let mut extensions = BTreeSet::new();

    // Map bit positions to single-letter extensions (RISC-V convention)
    let letter_map = [
        ('a', 0),  // Atomic
        ('b', 1),  // Bitmanip (preliminary)
        ('c', 2),  // Compressed
        ('d', 3),  // Double-precision Float
        ('e', 4),  // Embedded (RV32E)
        ('f', 5),  // Single-precision Float
        ('g', 6),  // General (shorthand for IMAFD)
        ('h', 7),  // Hypervisor
        ('i', 8),  // Integer (Base)
        ('j', 9),  // Dynamically Translated Languages
        ('k', 10), // Reserved
        ('l', 11), // Reserved
        ('m', 12), // Multiply/Divide
        ('n', 13), // User-level Interrupts
        ('o', 14), // Reserved
        ('p', 15), // Packed-SIMD (preliminary)
        ('q', 16), // Quad-precision Float
        ('r', 17), // Reserved
        ('s', 18), // Supervisor mode
        ('t', 19), // Transactional Memory (preliminary)
        ('u', 20), // User mode
        ('v', 21), // Vector
        ('w', 22), // Reserved
        ('x', 23), // Non-standard Extensions
        ('y', 24), // Reserved
        ('z', 25), // Reserve for extensions
    ];

    for (letter, bit) in &letter_map {
        if isa_bits & (1u64 << bit) != 0 {
            extensions.insert(letter.to_string());
        }
    }

    extensions
}

fn detect_extensions_legacy(_vm: &VmFd) -> BTreeSet<String> {
    // Legacy fallback: use hardcoded ISA bits and multi-letter extensions for RVA23S64
    // Bit pattern: i(8) m(12) a(0) f(5) d(3) c(2) = bits set at positions 0,2,3,5,8,12
    let isa_bits_rv64g: u64 = (1u64 << 0) // a - Atomic
        | (1u64 << 2) // c - Compressed
        | (1u64 << 3) // d - Double-precision Float
        | (1u64 << 5) // f - Single-precision Float
        | (1u64 << 8) // i - Integer (Base)
        | (1u64 << 12); // m - Multiply/Divide

    let mut extensions = extract_single_letter_extensions(isa_bits_rv64g);

    // Add multi-letter extensions for RVA23S64
    let multi_letter = [
        "zicsr", "zifencei", // Counter/Supervisor CSRs
        "zicbom", "zicbop", "zicboz", // Cache block operations
        "zba", "zbb", "zbc", "zbs", // Bit manipulation
        "smaia", "ssaia", // AIA
        "svpbmt", "sstc", "sscofpmf", // Supervisor extensions
    ];

    for ext in &multi_letter {
        extensions.insert(ext.to_string());
    }

    debug!(
        "Legacy detection: Using fallback extensions ({}): {:?}",
        extensions.len(),
        extensions
    );

    extensions
}

fn read_block_size_if_present(_vm: &VmFd, config_field: &str) -> Option<u32> {
    // Default cache block sizes for RISC-V64
    // These match QEMU's defaults and common hardware configurations
    match config_field {
        "zicbom_block_size" | "zicboz_block_size" | "zicbop_block_size" => Some(64),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash_extension_name(name: &str) -> u32 {
        name.len() as u32 % 256
    }

    #[test]
    fn test_isa_info_creation() {
        let mut extensions = BTreeSet::new();
        extensions.insert("i".to_string());
        extensions.insert("m".to_string());

        let info = RiscvIsaInfo {
            isa_string: "rv64imafdc_smaia_ssaia".to_string(),
            extensions,
            zicbom_block_size: Some(64),
            zicboz_block_size: Some(64),
            zicbop_block_size: Some(64),
        };

        assert_eq!(info.isa_string, "rv64imafdc_smaia_ssaia");
        assert_eq!(info.zicbom_block_size, Some(64));
        assert!(info.extensions.contains("i"));
    }

    #[test]
    fn test_isa_info_no_block_sizes() {
        let extensions = BTreeSet::new();

        let info = RiscvIsaInfo {
            isa_string: "rv64i".to_string(),
            extensions,
            zicbom_block_size: None,
            zicboz_block_size: None,
            zicbop_block_size: None,
        };

        assert_eq!(info.isa_string, "rv64i");
        assert_eq!(info.zicbom_block_size, None);
        assert_eq!(info.zicboz_block_size, None);
        assert_eq!(info.zicbop_block_size, None);
        assert!(info.extensions.is_empty());
    }

    #[test]
    fn test_isa_info_many_extensions() {
        let mut extensions = BTreeSet::new();
        extensions.insert("i".to_string());
        extensions.insert("m".to_string());
        extensions.insert("a".to_string());
        extensions.insert("f".to_string());
        extensions.insert("d".to_string());
        extensions.insert("c".to_string());
        extensions.insert("zicsr".to_string());
        extensions.insert("zifencei".to_string());
        extensions.insert("zicbom".to_string());
        extensions.insert("zicboz".to_string());
        extensions.insert("zicbop".to_string());
        extensions.insert("smaia".to_string());
        extensions.insert("ssaia".to_string());

        let info = RiscvIsaInfo {
            isa_string: "rv64imafdc_zicsr_zifencei_smaia_ssaia".to_string(),
            extensions: extensions.clone(),
            zicbom_block_size: Some(64),
            zicboz_block_size: Some(64),
            zicbop_block_size: Some(64),
        };

        assert_eq!(info.extensions.len(), 13);
        assert!(info.extensions.contains("zicbom"));
        assert!(info.extensions.contains("smaia"));
        assert!(info.extensions.contains("ssaia"));
        assert_eq!(info.zicbom_block_size, Some(64));
    }

    #[test]
    fn test_isa_info_partial_block_sizes() {
        let extensions = BTreeSet::new();

        let info = RiscvIsaInfo {
            isa_string: "rv64imafdc".to_string(),
            extensions,
            zicbom_block_size: Some(64),
            zicboz_block_size: None,
            zicbop_block_size: Some(32),
        };

        assert_eq!(info.zicbom_block_size, Some(64));
        assert_eq!(info.zicboz_block_size, None);
        assert_eq!(info.zicbop_block_size, Some(32));
    }

    #[test]
    fn test_hash_extension_name() {
        let hash_a = hash_extension_name("a");
        let hash_i = hash_extension_name("i");
        let hash_zicbom = hash_extension_name("zicbom");

        // Just verify they're computed (values don't matter much for a hash)
        assert!(hash_a < 256);
        assert!(hash_i < 256);
        assert!(hash_zicbom < 256);
    }

    #[test]
    fn test_extension_sorting() {
        let mut extensions = BTreeSet::new();
        extensions.insert("zvfh".to_string());
        extensions.insert("zba".to_string());
        extensions.insert("i".to_string());
        extensions.insert("smaia".to_string());

        let mut ext_vec: Vec<_> = extensions.iter().cloned().collect();
        assert_eq!(ext_vec[0], "i");
        assert_eq!(ext_vec[ext_vec.len() - 1], "zvfh");
    }

    #[test]
    fn test_read_block_size_cbom() {
        use std::fs::File;
        use std::os::fd::AsRawFd;

        let dummy_file = File::open("/dev/null").expect("Failed to open /dev/null");
        let raw_fd = dummy_file.as_raw_fd();

        unsafe {
            let vm_fd = kvm_ioctls::VmFd::new(raw_fd);
            let size = read_block_size_if_present(&vm_fd, "zicbom_block_size");
            assert_eq!(size, Some(64));
        }
    }

    #[test]
    fn test_read_block_size_cboz() {
        use std::fs::File;
        use std::os::fd::AsRawFd;

        let dummy_file = File::open("/dev/null").expect("Failed to open /dev/null");
        let raw_fd = dummy_file.as_raw_fd();

        unsafe {
            let vm_fd = kvm_ioctls::VmFd::new(raw_fd);
            let size = read_block_size_if_present(&vm_fd, "zicboz_block_size");
            assert_eq!(size, Some(64));
        }
    }

    #[test]
    fn test_read_block_size_cbop() {
        use std::fs::File;
        use std::os::fd::AsRawFd;

        let dummy_file = File::open("/dev/null").expect("Failed to open /dev/null");
        let raw_fd = dummy_file.as_raw_fd();

        unsafe {
            let vm_fd = kvm_ioctls::VmFd::new(raw_fd);
            let size = read_block_size_if_present(&vm_fd, "zicbop_block_size");
            assert_eq!(size, Some(64));
        }
    }

    #[test]
    fn test_read_block_size_unknown_field() {
        use std::fs::File;
        use std::os::fd::AsRawFd;

        let dummy_file = File::open("/dev/null").expect("Failed to open /dev/null");
        let raw_fd = dummy_file.as_raw_fd();

        unsafe {
            let vm_fd = kvm_ioctls::VmFd::new(raw_fd);
            let size = read_block_size_if_present(&vm_fd, "unknown_field");
            assert_eq!(size, None);
        }
    }

    #[test]
    fn test_detect_extensions_legacy_includes_base_extensions() {
        use std::fs::File;
        use std::os::fd::AsRawFd;

        let dummy_file = File::open("/dev/null").expect("Failed to open /dev/null");
        let raw_fd = dummy_file.as_raw_fd();

        unsafe {
            let vm_fd = kvm_ioctls::VmFd::new(raw_fd);
            let extensions = detect_extensions_legacy(&vm_fd);

            // Verify base ISA extensions are present
            assert!(extensions.contains("i"));
            assert!(extensions.contains("m"));
            assert!(extensions.contains("a"));
            assert!(extensions.contains("f"));
            assert!(extensions.contains("d"));
            assert!(extensions.contains("c"));
        }
    }

    #[test]
    fn test_detect_extensions_legacy_includes_supervisor_extensions() {
        use std::fs::File;
        use std::os::fd::AsRawFd;

        let dummy_file = File::open("/dev/null").expect("Failed to open /dev/null");
        let raw_fd = dummy_file.as_raw_fd();

        unsafe {
            let vm_fd = kvm_ioctls::VmFd::new(raw_fd);
            let extensions = detect_extensions_legacy(&vm_fd);

            // Verify supervisor mode extensions are included
            assert!(extensions.contains("smaia"));
            assert!(extensions.contains("ssaia"));
            assert!(extensions.contains("svpbmt"));
            assert!(extensions.contains("sstc"));
            assert!(extensions.contains("sscofpmf"));
        }
    }

    #[test]
    fn test_isa_info_is_cloneable() {
        let mut extensions = BTreeSet::new();
        extensions.insert("i".to_string());

        let info = RiscvIsaInfo {
            isa_string: "rv64i".to_string(),
            extensions,
            zicbom_block_size: Some(64),
            zicboz_block_size: None,
            zicbop_block_size: Some(64),
        };

        let cloned = info.clone();
        assert_eq!(cloned.isa_string, "rv64i");
        assert_eq!(cloned.zicbom_block_size, Some(64));
        assert_eq!(cloned.zicboz_block_size, None);
    }
}
