use crate::Binary;
use crate::Config;
use crate::Coverage;
use crate::Diff;
use crate::DiffValues;
use crate::LoadedInputs;
use crate::Report;
use crate::Result;
use crate::arch::Arch;
use crate::arch::ArchKind;
use crate::first_equals_any;
use crate::section_map::LayoutAndFiles;
use anyhow::bail;
use itertools::Itertools as _;
#[allow(clippy::wildcard_imports)]
use linker_utils::elf::secnames::*;
use object::LittleEndian;

type ElfFile64<'data> = object::read::elf::ElfFile64<'data, LittleEndian>;

pub(crate) fn report_from_config(mut config: Config, inputs: LoadedInputs) -> Result<Report> {
    let elf_files = inputs
        .file_bytes
        .iter()
        .map(|bytes| -> Result<ElfFile64> { Ok(ElfFile64::parse(bytes.as_slice())?) })
        .collect::<Result<Vec<_>>>()?;

    let layouts = config
        .filenames()
        .map(|p| LayoutAndFiles::from_base_path(p))
        .collect::<Result<Vec<_>>>()?;

    let objects = elf_files
        .iter()
        .zip(inputs.display_names)
        .zip(config.filenames())
        .zip(&layouts)
        .map(|(((elf_file, name), path), layout)| -> Result<Binary> {
            Binary::new(elf_file, name, path.clone(), layout.as_ref())
        })
        .collect::<Result<Vec<_>>>()?;

    if objects.len() < 2 {
        bail!("At least two files must be provided for comparison");
    }

    let arch = ArchKind::from_objects(&objects)?;

    if config.wild_defaults {
        config.apply_wild_defaults(arch);
    }

    let paths = objects.iter().map(|o| o.path.clone()).collect();
    let names = objects.iter().map(|o| o.name.clone()).collect();
    let coverage = config.coverage.then(Coverage::default);
    let mut report = Report::new(config, names, paths, coverage);

    run_on_objects(&mut report, &objects, arch);

    Ok(report)
}

fn run_on_objects(report: &mut Report, objects: &[Binary], arch: ArchKind) {
    validate_objects(
        report,
        objects,
        GNU_HASH_SECTION_NAME_STR,
        crate::gnu_hash::check_object,
    );
    validate_objects(
        report,
        objects,
        HASH_SECTION_NAME_STR,
        crate::sysv_hash::check_object,
    );
    validate_objects(report, objects, "index", crate::asm_diff::validate_indexes);
    validate_objects(
        report,
        objects,
        GOT_PLT_SECTION_NAME_STR,
        crate::asm_diff::validate_got_plt,
    );
    validate_objects(
        report,
        objects,
        SYMTAB_SECTION_NAME_STR,
        crate::symtab::validate_debug,
    );
    validate_objects(
        report,
        objects,
        DYNSYM_SECTION_NAME_STR,
        crate::symtab::validate_dynamic,
    );
    crate::header_diff::check_dynamic_headers(report, objects);
    crate::header_diff::check_file_headers(report, objects);
    crate::header_diff::report_section_diffs(report, objects);
    crate::eh_frame_diff::report_diffs(report, objects);
    crate::version_diff::report_diffs(report, objects);
    crate::debug_info_diff::check_debug_info(report, objects);
    crate::symbol_diff::report_diffs(report, objects);
    crate::segment::report_diffs(report, objects);

    match arch {
        ArchKind::X86_64 => {
            report_arch_specific_diffs::<crate::x86_64::X86_64>(report, objects);
        }
        ArchKind::Aarch64 => {
            report_arch_specific_diffs::<crate::aarch64::AArch64>(report, objects);
        }

        ArchKind::RISCV64 => {
            report_arch_specific_diffs::<crate::riscv64::RiscV64>(report, objects);
            crate::riscv_attributes::report_diffs(report, objects);
        }
        ArchKind::LoongArch64 => {
            report_arch_specific_diffs::<crate::loongarch64::LoongArch64>(report, objects);
        }
    }
}

fn report_arch_specific_diffs<A: Arch>(report: &mut Report, binaries: &[Binary]) {
    crate::asm_diff::report_section_diffs::<A>(report, binaries);
    crate::init_order::report_diffs::<A>(report, binaries);
}

fn validate_objects(
    report: &mut Report,
    objects: &[Binary],
    validation_name: &str,
    validation_fn: impl Fn(&Binary) -> Result,
) {
    let values = objects
        .iter()
        .map(|obj| match validation_fn(obj) {
            Ok(_) => "OK".to_owned(),
            Err(e) => e.to_string(),
        })
        .collect_vec();
    if first_equals_any(values.iter()) {
        return;
    }
    report.add_diff(Diff {
        key: validation_name.to_owned(),
        values: DiffValues::PerObject(values),
    });
}
