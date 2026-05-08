//! Owned COFF input model for PE linking.

use crate::args::Input;
use crate::args::InputSpec;
use crate::args::pe::PeArgs;
use crate::bail;
use crate::error::Context as _;
use crate::error::Result;
use object::Object as _;
use object::ObjectSection as _;
use object::ObjectSymbol as _;
use object::read::RelocationTarget;
use object::read::SectionIndex;
use object::read::SymbolIndex;
use object::read::SymbolSection;
use object::read::archive::ArchiveFile;
use object::read::archive::ArchiveOffset;
use std::collections::HashMap;
use std::collections::HashSet;
use std::path::Path;
use std::path::PathBuf;

pub(crate) struct InputObject {
    pub(crate) path: PathBuf,
    pub(crate) sections: Vec<InputSection>,
    pub(crate) symbols: Vec<InputSymbol>,
}

struct InputArchive {
    path: PathBuf,
    data: Vec<u8>,
    members_by_symbol: HashMap<String, ArchiveMemberRef>,
}

#[derive(Clone, Copy)]
struct ArchiveMemberRef {
    offset: ArchiveOffset,
}

pub(crate) struct InputSection {
    pub(crate) index: SectionIndex,
    pub(crate) name: Vec<u8>,
    pub(crate) data: Vec<u8>,
    pub(crate) size: u32,
    pub(crate) characteristics: u32,
    pub(crate) relocations: Vec<InputRelocation>,
    pub(crate) output_section: Option<usize>,
    pub(crate) output_offset: u32,
}

pub(crate) struct InputRelocation {
    pub(crate) offset: u32,
    pub(crate) target: InputRelocationTarget,
    pub(crate) typ: u16,
}

#[derive(Clone, Copy)]
pub(crate) enum InputRelocationTarget {
    Symbol(SymbolIndex),
    Section(SectionIndex),
    Absolute,
}

#[derive(Clone)]
pub(crate) struct InputSymbol {
    pub(crate) name: Option<String>,
    pub(crate) section: SymbolSection,
    pub(crate) value: u64,
    pub(crate) is_undefined: bool,
    pub(crate) is_definition: bool,
    pub(crate) is_local: bool,
}

impl InputSymbol {
    fn placeholder() -> Self {
        Self {
            name: None,
            section: SymbolSection::None,
            value: 0,
            is_undefined: true,
            is_definition: false,
            is_local: true,
        }
    }
}

pub(crate) fn load_input_objects(args: &PeArgs) -> Result<Vec<InputObject>> {
    let mut objects = Vec::new();
    let mut archives = Vec::new();
    for input in &args.common.inputs {
        let path = resolve_input_path(input, args)?;
        let data =
            std::fs::read(&path).with_context(|| format!("failed to read `{}`", path.display()))?;
        match object::FileKind::parse(data.as_slice())
            .with_context(|| format!("failed to identify `{}`", path.display()))?
        {
            object::FileKind::Coff | object::FileKind::CoffBig => {
                objects.push(parse_input_object(path, &data)?);
            }
            object::FileKind::Archive => {
                archives.push(parse_archive(path, data)?);
            }
            object::FileKind::CoffImport => {
                bail!(
                    "COFF import library members are not supported yet: `{}`",
                    path.display()
                );
            }
            kind => bail!("unsupported PE input kind {kind:?}: `{}`", path.display()),
        }
    }

    load_archive_members(&mut objects, &archives)?;

    Ok(objects)
}

fn parse_archive(path: PathBuf, data: Vec<u8>) -> Result<InputArchive> {
    let archive = ArchiveFile::parse(data.as_slice())
        .with_context(|| format!("failed to parse COFF archive `{}`", path.display()))?;
    let mut members_by_symbol = HashMap::new();
    if let Some(symbols) = archive
        .symbols()
        .with_context(|| format!("failed to read archive symbols in `{}`", path.display()))?
    {
        for symbol in symbols {
            let symbol = symbol.with_context(|| {
                format!("failed to read archive symbol in `{}`", path.display())
            })?;
            let name = String::from_utf8_lossy(symbol.name()).into_owned();
            members_by_symbol.entry(name).or_insert(ArchiveMemberRef {
                offset: symbol.offset(),
            });
        }
    }

    Ok(InputArchive {
        path,
        data,
        members_by_symbol,
    })
}

fn load_archive_members(objects: &mut Vec<InputObject>, archives: &[InputArchive]) -> Result {
    let mut loaded_members = HashSet::new();

    loop {
        let definitions = external_definitions(objects);
        let unresolved = unresolved_externals(objects, &definitions);
        let mut loaded_any = false;

        for name in unresolved {
            if definitions.contains(&name) {
                continue;
            }

            for (archive_index, archive) in archives.iter().enumerate() {
                let Some(member_ref) = archive.members_by_symbol.get(&name) else {
                    continue;
                };
                let member_key = (archive_index, member_ref.offset.0);
                if !loaded_members.insert(member_key) {
                    continue;
                }

                objects.push(load_archive_member(archive, *member_ref)?);
                loaded_any = true;
                break;
            }
        }

        if !loaded_any {
            break;
        }
    }

    Ok(())
}

fn external_definitions(objects: &[InputObject]) -> HashSet<String> {
    objects
        .iter()
        .flat_map(|object| &object.symbols)
        .filter(|symbol| symbol.is_definition && !symbol.is_local)
        .filter_map(|symbol| symbol.name.clone())
        .collect()
}

fn unresolved_externals(objects: &[InputObject], definitions: &HashSet<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut unresolved = Vec::new();
    for symbol in objects
        .iter()
        .flat_map(|object| &object.symbols)
        .filter(|symbol| symbol.is_undefined && !symbol.is_local)
    {
        let Some(name) = &symbol.name else {
            continue;
        };
        if !definitions.contains(name) && seen.insert(name.clone()) {
            unresolved.push(name.clone());
        }
    }
    unresolved
}

fn load_archive_member(
    archive: &InputArchive,
    member_ref: ArchiveMemberRef,
) -> Result<InputObject> {
    let archive_file = ArchiveFile::parse(archive.data.as_slice())
        .with_context(|| format!("failed to parse COFF archive `{}`", archive.path.display()))?;
    let member = archive_file.member(member_ref.offset).with_context(|| {
        format!(
            "failed to read archive member at offset {} in `{}`",
            member_ref.offset.0,
            archive.path.display()
        )
    })?;
    let member_name = String::from_utf8_lossy(member.name()).into_owned();
    let member_data = member.data(archive.data.as_slice()).with_context(|| {
        format!(
            "failed to read archive member `{member_name}` in `{}`",
            archive.path.display()
        )
    })?;
    match object::FileKind::parse(member_data).with_context(|| {
        format!(
            "failed to identify archive member `{member_name}` in `{}`",
            archive.path.display()
        )
    })? {
        object::FileKind::Coff | object::FileKind::CoffBig => {}
        object::FileKind::CoffImport => {
            bail!(
                "COFF import library members are not supported yet: `{}({member_name})`",
                archive.path.display()
            );
        }
        kind => bail!(
            "unsupported COFF archive member kind {kind:?}: `{}({member_name})`",
            archive.path.display()
        ),
    }

    let synthetic_path = PathBuf::from(format!("{}({member_name})", archive.path.display()));
    parse_input_object(synthetic_path, member_data)
}

fn resolve_input_path(input: &Input, args: &PeArgs) -> Result<PathBuf> {
    match &input.spec {
        InputSpec::File(path) => {
            let path = PathBuf::from(path.as_ref());
            if path.exists() {
                return Ok(path);
            }
            search_path(&path, input, args)
        }
        InputSpec::Search(name) => search_path(Path::new(name.as_ref()), input, args),
        InputSpec::Lib(name) => {
            let mut lib_name = PathBuf::from(name.as_ref());
            lib_name.set_extension("lib");
            search_path(&lib_name, input, args)
        }
    }
}

fn search_path(path: &Path, input: &Input, args: &PeArgs) -> Result<PathBuf> {
    if let Some(search_first) = &input.search_first {
        let candidate = search_first.join(path);
        if candidate.exists() {
            return Ok(candidate);
        }
    }

    for dir in &args.lib_search_path {
        let candidate = dir.join(path);
        if candidate.exists() {
            return Ok(candidate);
        }
    }

    bail!("unable to find PE input `{}`", path.display())
}

fn parse_input_object(path: PathBuf, data: &[u8]) -> Result<InputObject> {
    let file = object::File::parse(data)
        .with_context(|| format!("failed to parse COFF object `{}`", path.display()))?;

    let mut sections = Vec::new();
    for section in file.sections() {
        let index = section.index();
        let name = section
            .name_bytes()
            .with_context(|| format!("failed to read section name in `{}`", path.display()))?
            .to_vec();
        let characteristics = match section.flags() {
            object::SectionFlags::Coff { characteristics } => characteristics,
            flags => bail!(
                "expected COFF section flags in `{}`, got {flags:?}",
                path.display()
            ),
        };
        let data = section
            .data()
            .with_context(|| {
                format!(
                    "failed to read section `{}` data in `{}`",
                    String::from_utf8_lossy(&name),
                    path.display()
                )
            })?
            .to_vec();
        let relocations = section
            .relocations()
            .map(|(offset, relocation)| {
                let typ = match relocation.flags() {
                    object::RelocationFlags::Coff { typ } => typ,
                    flags => {
                        bail!(
                            "expected COFF relocation flags in `{}`, got {flags:?}",
                            path.display()
                        )
                    }
                };
                let target = match relocation.target() {
                    RelocationTarget::Symbol(index) => InputRelocationTarget::Symbol(index),
                    RelocationTarget::Section(index) => InputRelocationTarget::Section(index),
                    RelocationTarget::Absolute => InputRelocationTarget::Absolute,
                    target => bail!(
                        "unsupported relocation target {target:?} in `{}`",
                        path.display()
                    ),
                };
                Ok(InputRelocation {
                    offset: offset.try_into().with_context(|| {
                        format!("relocation offset too large in `{}`", path.display())
                    })?,
                    target,
                    typ,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        sections.push(InputSection {
            index,
            name,
            data,
            size: section
                .size()
                .try_into()
                .with_context(|| format!("section too large in `{}`", path.display()))?,
            characteristics,
            relocations,
            output_section: None,
            output_offset: 0,
        });
    }

    let mut symbols = Vec::new();
    for symbol in file.symbols() {
        let symbol_index = symbol.index().0;
        if symbols.len() <= symbol_index {
            symbols.resize_with(symbol_index + 1, InputSymbol::placeholder);
        }
        let name = symbol
            .name()
            .ok()
            .filter(|name| !name.is_empty())
            .map(str::to_owned);
        symbols[symbol_index] = InputSymbol {
            name,
            section: symbol.section(),
            value: symbol.address(),
            is_undefined: symbol.is_undefined(),
            is_definition: symbol.is_definition(),
            is_local: symbol.is_local(),
        };
    }

    Ok(InputObject {
        path,
        sections,
        symbols,
    })
}
