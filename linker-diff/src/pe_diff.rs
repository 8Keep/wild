use crate::Config;
use crate::Diff;
use crate::DiffValues;
use crate::LoadedInputs;
use crate::Report;
use crate::Result;
use crate::first_equals_any;
use anyhow::bail;
use hashbrown::HashSet;
use itertools::Itertools as _;
use object::LittleEndian;
use object::Object as _;
use object::ObjectSection as _;
use object::pe;
use object::read::pe::ImageNtHeaders as _;
use object::read::pe::ImageOptionalHeader as _;
use object::read::pe::PeFile64;
use std::collections::BTreeSet;

pub(crate) fn report_from_config(config: Config, inputs: LoadedInputs) -> Result<Report> {
    if config.coverage {
        bail!("Coverage reporting is not supported for PE files");
    }

    let files = inputs
        .file_bytes
        .iter()
        .map(|bytes| PeFile64::parse(bytes.as_slice()))
        .collect::<Result<Vec<_>, _>>()?;
    if files.len() < 2 {
        bail!("At least two files must be provided for comparison");
    }

    let facts = files
        .iter()
        .map(PeFacts::parse)
        .collect::<Result<Vec<_>>>()?;

    let paths = config.filenames().cloned().collect();
    let mut report = Report::new(config, inputs.display_names, paths, None);

    compare_value(&mut report, &facts, "pe.machine", |facts| {
        format!("{:#x}", facts.machine)
    });
    compare_value(&mut report, &facts, "pe.subsystem", |facts| {
        format!("{:#x}", facts.subsystem)
    });
    compare_value(&mut report, &facts, "pe.characteristics", |facts| {
        facts.characteristics.clone()
    });
    compare_value(&mut report, &facts, "pe.entry", |facts| {
        if facts.has_entry {
            "present".to_owned()
        } else {
            "absent".to_owned()
        }
    });
    compare_value(&mut report, &facts, "pe.sections", |facts| {
        facts.sections.join(",")
    });
    compare_value(&mut report, &facts, "pe.data-directories", |facts| {
        facts.data_directories.join(",")
    });
    compare_value(&mut report, &facts, "pe.imports", |facts| {
        facts.imports.join(",")
    });
    compare_value(&mut report, &facts, "pe.base-relocations", |facts| {
        facts.base_relocations.clone()
    });

    Ok(report)
}

struct PeFacts {
    machine: u16,
    subsystem: u16,
    characteristics: String,
    has_entry: bool,
    sections: Vec<String>,
    data_directories: Vec<String>,
    imports: Vec<String>,
    base_relocations: String,
}

impl PeFacts {
    fn parse<'data>(file: &PeFile64<'data, &'data [u8]>) -> Result<Self> {
        let headers = file.nt_headers();
        let file_header = headers.file_header();
        let optional_header = headers.optional_header();

        Ok(Self {
            machine: file_header.machine.get(LittleEndian),
            subsystem: optional_header.subsystem(),
            characteristics: file_characteristics(file_header.characteristics.get(LittleEndian)),
            has_entry: optional_header.address_of_entry_point() != 0,
            sections: sections(file)?,
            data_directories: data_directories(file),
            imports: imports(file)?,
            base_relocations: base_relocations(file)?,
        })
    }
}

fn compare_value(
    report: &mut Report,
    facts: &[PeFacts],
    key: &str,
    value: impl Fn(&PeFacts) -> String,
) {
    let values = facts.iter().map(value).collect_vec();
    if first_equals_any(values.iter()) {
        return;
    }
    report.add_diff(Diff {
        key: key.to_owned(),
        values: DiffValues::PerObject(values),
    });
}

fn file_characteristics(characteristics: u16) -> String {
    let mut out = Vec::new();
    if characteristics & pe::IMAGE_FILE_EXECUTABLE_IMAGE != 0 {
        out.push("executable");
    }
    if characteristics & pe::IMAGE_FILE_DLL != 0 {
        out.push("dll");
    }
    if characteristics & pe::IMAGE_FILE_LARGE_ADDRESS_AWARE != 0 {
        out.push("large-address-aware");
    }
    if characteristics & pe::IMAGE_FILE_RELOCS_STRIPPED != 0 {
        out.push("relocs-stripped");
    }
    if out.is_empty() {
        "none".to_owned()
    } else {
        out.join("|")
    }
}

fn sections<'data>(file: &PeFile64<'data, &'data [u8]>) -> Result<Vec<String>> {
    let mut sections = Vec::new();
    for section in file.sections() {
        let name = section.name().unwrap_or("<invalid>");
        let characteristics = match section.flags() {
            object::SectionFlags::Coff { characteristics } => {
                section_characteristics(characteristics)
            }
            _ => "unknown".to_owned(),
        };
        sections.push(format!("{name}:{characteristics}"));
    }
    sections.sort();
    Ok(sections)
}

fn section_characteristics(characteristics: u32) -> String {
    let mut out = Vec::new();
    if characteristics & pe::IMAGE_SCN_CNT_CODE != 0 {
        out.push("code");
    }
    if characteristics & pe::IMAGE_SCN_CNT_INITIALIZED_DATA != 0 {
        out.push("idata");
    }
    if characteristics & pe::IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0 {
        out.push("bss");
    }
    if characteristics & pe::IMAGE_SCN_MEM_EXECUTE != 0 {
        out.push("x");
    }
    if characteristics & pe::IMAGE_SCN_MEM_READ != 0 {
        out.push("r");
    }
    if characteristics & pe::IMAGE_SCN_MEM_WRITE != 0 {
        out.push("w");
    }
    if characteristics & pe::IMAGE_SCN_MEM_DISCARDABLE != 0 {
        out.push("discard");
    }
    if out.is_empty() {
        "none".to_owned()
    } else {
        out.join("|")
    }
}

fn data_directories<'data>(file: &PeFile64<'data, &'data [u8]>) -> Vec<String> {
    DATA_DIRECTORIES
        .iter()
        .filter_map(|(index, name)| {
            let directory = file.data_directory(*index)?;
            let virtual_address = directory.virtual_address.get(LittleEndian);
            let size = directory.size.get(LittleEndian);
            (virtual_address != 0 && size != 0).then(|| (*name).to_owned())
        })
        .collect()
}

fn imports<'data>(file: &PeFile64<'data, &'data [u8]>) -> Result<Vec<String>> {
    let mut imports = file
        .imports()?
        .into_iter()
        .map(|import| {
            let library = String::from_utf8_lossy(import.library()).to_ascii_lowercase();
            let name = String::from_utf8_lossy(import.name());
            format!("{library}!{name}")
        })
        .collect::<HashSet<_>>()
        .into_iter()
        .collect_vec();
    imports.sort();
    Ok(imports)
}

fn base_relocations<'data>(file: &PeFile64<'data, &'data [u8]>) -> Result<String> {
    let Some(relocation_blocks) = file
        .data_directories()
        .relocation_blocks(file.data(), &file.section_table())?
    else {
        return Ok("absent".to_owned());
    };
    let mut blocks = 0usize;
    let mut entries = 0usize;
    let mut pages = BTreeSet::new();
    let mut types = BTreeSet::new();
    for block in relocation_blocks {
        let block = block?;
        blocks += 1;
        pages.insert(block.virtual_address());
        for relocation in block {
            if relocation.typ == pe::IMAGE_REL_BASED_ABSOLUTE {
                continue;
            }
            entries += 1;
            types.insert(relocation.typ);
        }
    }
    if blocks == 0 {
        return Ok("absent".to_owned());
    }
    Ok(format!(
        "blocks={blocks},entries={entries},pages={},types={}",
        pages.len(),
        types.into_iter().map(relocation_type_name).join("|")
    ))
}

fn relocation_type_name(typ: u16) -> String {
    match typ {
        pe::IMAGE_REL_BASED_ABSOLUTE => "ABSOLUTE".to_owned(),
        pe::IMAGE_REL_BASED_HIGH => "HIGH".to_owned(),
        pe::IMAGE_REL_BASED_LOW => "LOW".to_owned(),
        pe::IMAGE_REL_BASED_HIGHLOW => "HIGHLOW".to_owned(),
        pe::IMAGE_REL_BASED_HIGHADJ => "HIGHADJ".to_owned(),
        pe::IMAGE_REL_BASED_DIR64 => "DIR64".to_owned(),
        typ => format!("0x{typ:x}"),
    }
}

const DATA_DIRECTORIES: &[(usize, &str)] = &[
    (pe::IMAGE_DIRECTORY_ENTRY_EXPORT, "export"),
    (pe::IMAGE_DIRECTORY_ENTRY_IMPORT, "import"),
    (pe::IMAGE_DIRECTORY_ENTRY_RESOURCE, "resource"),
    (pe::IMAGE_DIRECTORY_ENTRY_EXCEPTION, "exception"),
    (pe::IMAGE_DIRECTORY_ENTRY_SECURITY, "security"),
    (pe::IMAGE_DIRECTORY_ENTRY_BASERELOC, "basereloc"),
    (pe::IMAGE_DIRECTORY_ENTRY_DEBUG, "debug"),
    (pe::IMAGE_DIRECTORY_ENTRY_ARCHITECTURE, "architecture"),
    (pe::IMAGE_DIRECTORY_ENTRY_GLOBALPTR, "globalptr"),
    (pe::IMAGE_DIRECTORY_ENTRY_TLS, "tls"),
    (pe::IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, "load-config"),
    (pe::IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT, "bound-import"),
    (pe::IMAGE_DIRECTORY_ENTRY_IAT, "iat"),
    (pe::IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT, "delay-import"),
    (pe::IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR, "com-descriptor"),
];
