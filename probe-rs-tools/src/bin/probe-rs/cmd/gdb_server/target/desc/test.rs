use probe_rs::{CoreType, InstructionSet};

use super::TargetDescription;

#[test]
fn test_target_description_microbit() {
    let target_desc = TargetDescription::new(CoreType::Armv6m, InstructionSet::Thumb2);
    let description = target_desc.get_target_xml();

    insta::assert_snapshot!(description);
}

#[test]
fn test_target_with_features() {
    let mut target_desc = TargetDescription::new(CoreType::Armv6m, InstructionSet::Thumb2);
    target_desc.add_gdb_feature("org.probe-rs.feature1");
    target_desc.add_register_from_details("r0", 32, 0.into());
    target_desc.add_register_from_details("x1", 64, 1.into());
    target_desc.add_register_from_details("t2", 64, 2.into());

    target_desc.update_register_name("t2", "at2");
    target_desc.update_register_type("at2", "special_reg");

    target_desc.add_gdb_feature("org.probe-rs.feature2");
    target_desc.add_register_from_details("v4", 128, 4.into());

    let description = target_desc.get_target_xml();

    insta::assert_snapshot!(description);
}

mod memory_map {
    use probe_rs::CoreType;
    use probe_rs_rpc::chip::{GenericRegion, MemoryAccess, MemoryRegion, NvmRegion, RamRegion};
    use probe_rs_rpc::info::WireFlashSector;

    use super::super::gdb_memory_map_from_wire;

    fn nvm(start: u64, end: u64) -> MemoryRegion {
        MemoryRegion::Nvm(NvmRegion {
            name: None,
            range: (start, end),
            cores: vec![],
            is_alias: false,
            access: None,
        })
    }

    fn generic(start: u64, end: u64, access: Option<MemoryAccess>) -> MemoryRegion {
        MemoryRegion::Generic(GenericRegion {
            name: None,
            range: (start, end),
            cores: vec![],
            access,
        })
    }

    /// The RL78/G15's map, cut down: code flash with an algorithm, data flash without one, a
    /// ROM, and special function registers.
    fn map() -> String {
        let regions = [
            nvm(0x0, 0x2000),
            nvm(0x9000, 0x9400),
            generic(
                0xE_FE00,
                0xF_0000,
                Some(MemoryAccess {
                    write: false,
                    ..MemoryAccess::default()
                }),
            ),
            generic(0xF_FF00, 0x10_0000, None),
            MemoryRegion::Ram(RamRegion {
                name: None,
                range: (0xF_FB00, 0xF_FF00),
                cores: vec![],
                access: None,
            }),
        ];
        let sectors = [WireFlashSector {
            start: 0x0,
            length: 0x2000,
            blocksize: 0x400,
        }];
        gdb_memory_map_from_wire(&regions, &sectors, CoreType::Rl78, 32)
    }

    #[test]
    fn flash_with_an_algorithm_is_its_sectors() {
        let map = map();
        assert!(map.contains(r#"<memory type="flash" start="0x0" length="0x2000">"#));
        assert!(!map.contains(r#"<memory type="rom" start="0x0""#));
    }

    #[test]
    fn nvm_without_an_algorithm_is_still_readable() {
        assert!(map().contains(r#"<memory type="rom" start="0x9000" length="0x400"/>"#));
    }

    #[test]
    fn generic_regions_are_writable_unless_declared_not() {
        let map = map();
        assert!(map.contains(r#"<memory type="rom" start="0xefe00" length="0x200"/>"#));
        assert!(map.contains(r#"<memory type="ram" start="0xfff00" length="0x100"/>"#));
    }
}
