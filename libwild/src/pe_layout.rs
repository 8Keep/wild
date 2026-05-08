//! PE/COFF section layout and symbol address assignment.

use crate::args::pe::PeArgs;
use crate::bail;
use crate::error::Context as _;
use crate::error::Result;
use crate::pe_object::InputObject;
use crate::pe_object::InputRelocationTarget;
use object::pe;
use object::read::SectionIndex;
use object::read::SymbolSection;
use std::collections::HashMap;

pub(crate) const IMAGE_BASE_X64: u64 = 0x0000_0001_4000_0000;
pub(crate) const SECTION_ALIGNMENT: u32 = 0x1000;
pub(crate) const FILE_ALIGNMENT: u32 = 0x200;

pub(crate) struct PeLayout {
    pub(crate) image_base: u64,
    pub(crate) machine: u16,
    pub(crate) sections: Vec<OutputSection>,
    pub(crate) objects: Vec<InputObject>,
    pub(crate) symbol_addresses: HashMap<(usize, usize), u64>,
    pub(crate) global_definitions: HashMap<String, (usize, usize)>,
    pub(crate) entry_point_rva: u32,
    pub(crate) size_of_headers: u32,
    pub(crate) size_of_image: u32,
    pub(crate) file_size: u64,
}

pub(crate) struct OutputSection {
    pub(crate) name: [u8; 8],
    pub(crate) virtual_address: u32,
    pub(crate) virtual_size: u32,
    pub(crate) file_offset: u32,
    pub(crate) raw_data_size: u32,
    pub(crate) characteristics: u32,
    pub(crate) is_bss: bool,
    pub(crate) contributions: Vec<SectionContribution>,
}

pub(crate) struct SectionContribution {
    pub(crate) object_index: usize,
    pub(crate) section_index: usize,
    pub(crate) output_offset: u32,
    pub(crate) size: u32,
}

pub(crate) fn compute_layout(args: &PeArgs, mut objects: Vec<InputObject>) -> Result<PeLayout> {
    let image_base = args.base_address.unwrap_or(IMAGE_BASE_X64);
    let machine = pe::IMAGE_FILE_MACHINE_AMD64;

    let mut sections = Vec::new();
    let mut section_map = HashMap::new();
    for (object_index, object) in objects.iter_mut().enumerate() {
        for (section_index, section) in object.sections.iter_mut().enumerate() {
            if should_discard_section(section) {
                continue;
            }

            let out_name = output_section_name(&section.name);
            let out_chars = merge_characteristics(section.characteristics);
            let is_bss = section.characteristics & pe::IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0;
            let key = (out_name, out_chars, is_bss);
            let out_index = *section_map.entry(key).or_insert_with(|| {
                sections.push(OutputSection {
                    name: out_name,
                    virtual_address: 0,
                    virtual_size: 0,
                    file_offset: 0,
                    raw_data_size: 0,
                    characteristics: out_chars,
                    is_bss,
                    contributions: Vec::new(),
                });
                sections.len() - 1
            });

            let out_section = &mut sections[out_index];
            let alignment = coff_section_alignment(section.characteristics);
            let offset = align_up(out_section.virtual_size, alignment);
            section.output_section = Some(out_index);
            section.output_offset = offset;

            let size = section
                .size
                .max(section.data.len().try_into().unwrap_or(u32::MAX));
            out_section.virtual_size = offset
                .checked_add(size)
                .context("PE section virtual size overflow")?;
            if !is_bss {
                out_section.raw_data_size = out_section.virtual_size;
            }
            out_section.contributions.push(SectionContribution {
                object_index,
                section_index,
                output_offset: offset,
                size,
            });
        }
    }

    sections.sort_by_key(|section| section_sort_key(&section.name));
    remap_output_section_indices(&mut objects, &sections)?;

    let headers_raw = crate::pe_writer::headers_size(sections.len());
    let size_of_headers = align_up(headers_raw, FILE_ALIGNMENT);
    let mut next_rva = align_up(size_of_headers, SECTION_ALIGNMENT);
    let mut next_file_offset = size_of_headers;

    for section in &mut sections {
        section.virtual_address = next_rva;
        if section.is_bss {
            section.file_offset = 0;
        } else {
            section.file_offset = next_file_offset;
            section.raw_data_size = align_up(section.raw_data_size, FILE_ALIGNMENT);
            next_file_offset = next_file_offset
                .checked_add(section.raw_data_size)
                .context("PE file size overflow")?;
        }
        next_rva = align_up(
            next_rva
                .checked_add(section.virtual_size)
                .context("PE image size overflow")?,
            SECTION_ALIGNMENT,
        );
    }

    Ok(PeLayout {
        image_base,
        machine,
        sections,
        objects,
        symbol_addresses: HashMap::new(),
        global_definitions: HashMap::new(),
        entry_point_rva: 0,
        size_of_headers,
        size_of_image: next_rva,
        file_size: next_file_offset as u64,
    })
}

fn remap_output_section_indices(objects: &mut [InputObject], sections: &[OutputSection]) -> Result {
    let mut by_contribution = HashMap::new();
    for (new_index, section) in sections.iter().enumerate() {
        for contribution in &section.contributions {
            by_contribution.insert(
                (contribution.object_index, contribution.section_index),
                (new_index, contribution.output_offset),
            );
        }
    }

    for (object_index, object) in objects.iter_mut().enumerate() {
        for (section_index, section) in object.sections.iter_mut().enumerate() {
            if section.output_section.is_some() {
                let (new_index, output_offset) = by_contribution
                    .get(&(object_index, section_index))
                    .copied()
                    .context("internal PE section remap failure")?;
                section.output_section = Some(new_index);
                section.output_offset = output_offset;
            }
        }
    }

    Ok(())
}

pub(crate) fn resolve_symbols(layout: &mut PeLayout) -> Result {
    let mut section_by_index = HashMap::new();
    for (object_index, object) in layout.objects.iter().enumerate() {
        for (section_index, section) in object.sections.iter().enumerate() {
            section_by_index.insert((object_index, section.index), section_index);
        }
    }

    for (object_index, object) in layout.objects.iter().enumerate() {
        for (symbol_index, symbol) in object.symbols.iter().enumerate() {
            if symbol.is_definition
                && !symbol.is_local
                && let Some(name) = &symbol.name
                && let Some(section_id) = symbol.section.index()
            {
                let Some(section_index) = section_by_index.get(&(object_index, section_id)) else {
                    continue;
                };
                if object.sections[*section_index].output_section.is_none() {
                    continue;
                }
                if let Some((prev_object, _)) = layout
                    .global_definitions
                    .insert(name.clone(), (object_index, symbol_index))
                {
                    bail!(
                        "duplicate PE symbol `{name}` in `{}` and `{}`",
                        layout.objects[prev_object].path.display(),
                        object.path.display()
                    );
                }
            }
        }
    }

    for (object_index, object) in layout.objects.iter().enumerate() {
        for (symbol_index, symbol) in object.symbols.iter().enumerate() {
            let address = match symbol.section {
                SymbolSection::Section(section_id) => {
                    let section_index = section_by_index
                        .get(&(object_index, section_id))
                        .copied()
                        .with_context(|| {
                            format!(
                                "symbol references missing section {} in `{}`",
                                section_id,
                                object.path.display()
                            )
                        })?;
                    if object.sections[section_index].output_section.is_none() {
                        continue;
                    }
                    input_section_address(layout, object_index, section_index)? + symbol.value
                }
                SymbolSection::Absolute => symbol.value,
                SymbolSection::Undefined
                | SymbolSection::Unknown
                | SymbolSection::None
                | SymbolSection::Common => 0,
                _ => 0,
            };
            if address != 0 {
                layout
                    .symbol_addresses
                    .insert((object_index, symbol_index), address);
            }
        }
    }

    Ok(())
}

pub(crate) fn find_entry_point_rva(args: &PeArgs, layout: &PeLayout) -> Result<u32> {
    let entry_names: Vec<&str> = if let Some(entry) = &args.entry {
        vec![entry.as_str()]
    } else if args.is_dll {
        vec!["_DllMainCRTStartup"]
    } else {
        vec!["mainCRTStartup", "_mainCRTStartup", "WinMainCRTStartup"]
    };

    for name in entry_names {
        if let Some(&(object_index, symbol_index)) = layout.global_definitions.get(name) {
            let address = symbol_address(layout, object_index, symbol_index)?;
            return address
                .checked_sub(layout.image_base)
                .and_then(|rva| rva.try_into().ok())
                .with_context(|| format!("entry point `{name}` is outside PE image"));
        }
    }

    bail!("entry point symbol not found")
}

pub(crate) fn input_section_address(
    layout: &PeLayout,
    object_index: usize,
    section_index: usize,
) -> Result<u64> {
    let section = &layout.objects[object_index].sections[section_index];
    let output_section_index = section.output_section.with_context(|| {
        format!(
            "section `{}` from `{}` is not in the PE output",
            String::from_utf8_lossy(&section.name),
            layout.objects[object_index].path.display()
        )
    })?;
    let output_section = &layout.sections[output_section_index];
    Ok(layout.image_base
        + u64::from(output_section.virtual_address)
        + u64::from(section.output_offset))
}

pub(crate) fn symbol_address(
    layout: &PeLayout,
    object_index: usize,
    symbol_index: usize,
) -> Result<u64> {
    if let Some(address) = layout.symbol_addresses.get(&(object_index, symbol_index)) {
        return Ok(*address);
    }

    let symbol = layout.objects[object_index]
        .symbols
        .get(symbol_index)
        .with_context(|| {
            format!(
                "relocation references missing symbol index {symbol_index} in `{}`",
                layout.objects[object_index].path.display()
            )
        })?;
    if symbol.is_undefined
        && let Some(name) = &symbol.name
        && let Some(&(def_object, def_symbol)) = layout.global_definitions.get(name)
    {
        return symbol_address(layout, def_object, def_symbol);
    }

    bail!(
        "unable to resolve PE symbol `{}` in `{}`",
        symbol.name.as_deref().unwrap_or("<unnamed>"),
        layout.objects[object_index].path.display()
    )
}

pub(crate) fn section_symbol_index(
    layout: &PeLayout,
    object_index: usize,
    section_id: SectionIndex,
) -> Result<u16> {
    let section = layout.objects[object_index]
        .sections
        .iter()
        .find(|section| section.index == section_id)
        .with_context(|| {
            format!(
                "relocation references missing section {} in `{}`",
                section_id,
                layout.objects[object_index].path.display()
            )
        })?;
    let output_section = section
        .output_section
        .context("relocation references discarded section")?;
    Ok((output_section + 1)
        .try_into()
        .context("too many PE sections for SECTION relocation")?)
}

pub(crate) fn relocation_target_address(
    layout: &PeLayout,
    object_index: usize,
    target: &InputRelocationTarget,
) -> Result<u64> {
    match target {
        InputRelocationTarget::Symbol(symbol_index) => {
            symbol_address(layout, object_index, symbol_index.0)
        }
        InputRelocationTarget::Section(section_id) => {
            let section_index = layout.objects[object_index]
                .sections
                .iter()
                .position(|section| section.index == *section_id)
                .with_context(|| {
                    format!(
                        "relocation references missing section {} in `{}`",
                        section_id,
                        layout.objects[object_index].path.display()
                    )
                })?;
            input_section_address(layout, object_index, section_index)
        }
        InputRelocationTarget::Absolute => Ok(0),
    }
}

fn should_discard_section(section: &crate::pe_object::InputSection) -> bool {
    if section.characteristics & pe::IMAGE_SCN_MEM_DISCARDABLE != 0 {
        return true;
    }
    if section.size == 0 && section.data.is_empty() {
        return true;
    }
    merge_characteristics(section.characteristics) == 0
}

fn output_section_name(input_name: &[u8]) -> [u8; 8] {
    let base_name = input_name
        .iter()
        .position(|&b| b == b'$')
        .map_or(input_name, |pos| &input_name[..pos]);

    match base_name {
        b".text" => *b".text\0\0\0",
        b".rdata" => *b".rdata\0\0",
        b".data" => *b".data\0\0\0",
        b".bss" => *b".bss\0\0\0\0",
        b".pdata" => *b".pdata\0\0",
        b".xdata" => *b".xdata\0\0",
        _ => {
            let mut out = [0u8; 8];
            let len = base_name.len().min(8);
            out[..len].copy_from_slice(&base_name[..len]);
            out
        }
    }
}

fn merge_characteristics(chars: u32) -> u32 {
    chars
        & (pe::IMAGE_SCN_CNT_CODE
            | pe::IMAGE_SCN_CNT_INITIALIZED_DATA
            | pe::IMAGE_SCN_CNT_UNINITIALIZED_DATA
            | pe::IMAGE_SCN_MEM_EXECUTE
            | pe::IMAGE_SCN_MEM_READ
            | pe::IMAGE_SCN_MEM_WRITE)
}

fn coff_section_alignment(chars: u32) -> u32 {
    let align_field = (chars >> 20) & 0xF;
    if align_field == 0 {
        1
    } else {
        1 << (align_field - 1)
    }
}

fn section_sort_key(name: &[u8; 8]) -> u32 {
    match name {
        b".text\0\0\0" => 0,
        b".rdata\0\0" => 1,
        b".data\0\0\0" => 2,
        b".pdata\0\0" => 3,
        b".xdata\0\0" => 4,
        b".bss\0\0\0\0" => 5,
        _ => 10,
    }
}

pub(crate) fn align_up(value: u32, alignment: u32) -> u32 {
    (value + alignment - 1) & !(alignment - 1)
}
