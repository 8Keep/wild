//! x86_64 COFF relocation application for PE output.

use crate::bail;
use crate::error::Context as _;
use crate::error::Result;
use crate::pe_layout::OutputSection;
use crate::pe_layout::PeLayout;
use crate::pe_layout::SectionContribution;
use crate::pe_object::InputRelocationTarget;
use crate::pe_object::InputSection;
use object::pe;

pub(crate) fn apply_relocations(
    buf: &mut [u8],
    layout: &PeLayout,
    output_section: &OutputSection,
    contribution: &SectionContribution,
    input_section: &InputSection,
) -> Result {
    for relocation in &input_section.relocations {
        let file_offset = output_section.file_offset as usize
            + contribution.output_offset as usize
            + relocation.offset as usize;
        let reloc_va = layout.image_base
            + u64::from(output_section.virtual_address)
            + u64::from(contribution.output_offset)
            + u64::from(relocation.offset);
        let target_addr = crate::pe_layout::relocation_target_address(
            layout,
            contribution.object_index,
            &relocation.target,
        )?;

        match relocation.typ {
            pe::IMAGE_REL_AMD64_ABSOLUTE => {}
            pe::IMAGE_REL_AMD64_ADDR64 => write_u64(buf, file_offset, target_addr)?,
            pe::IMAGE_REL_AMD64_ADDR32 => {
                write_u32(buf, file_offset, checked_u32(target_addr, "ADDR32")?)?
            }
            pe::IMAGE_REL_AMD64_ADDR32NB => {
                let rva = target_addr
                    .checked_sub(layout.image_base)
                    .context("ADDR32NB target is below image base")?;
                write_u32(buf, file_offset, checked_u32(rva, "ADDR32NB")?)?
            }
            pe::IMAGE_REL_AMD64_REL32 => write_rel32(buf, file_offset, target_addr, reloc_va, 4)?,
            pe::IMAGE_REL_AMD64_REL32_1 => write_rel32(buf, file_offset, target_addr, reloc_va, 5)?,
            pe::IMAGE_REL_AMD64_REL32_2 => write_rel32(buf, file_offset, target_addr, reloc_va, 6)?,
            pe::IMAGE_REL_AMD64_REL32_3 => write_rel32(buf, file_offset, target_addr, reloc_va, 7)?,
            pe::IMAGE_REL_AMD64_REL32_4 => write_rel32(buf, file_offset, target_addr, reloc_va, 8)?,
            pe::IMAGE_REL_AMD64_REL32_5 => write_rel32(buf, file_offset, target_addr, reloc_va, 9)?,
            pe::IMAGE_REL_AMD64_SECTION => match relocation.target {
                InputRelocationTarget::Section(section_id) => {
                    write_u16(
                        buf,
                        file_offset,
                        crate::pe_layout::section_symbol_index(
                            layout,
                            contribution.object_index,
                            section_id,
                        )?,
                    )?;
                }
                InputRelocationTarget::Symbol(symbol_index) => {
                    let symbol = layout.objects[contribution.object_index]
                        .symbols
                        .get(symbol_index.0)
                        .context("SECTION relocation references missing symbol")?;
                    let section_id = symbol
                        .section
                        .index()
                        .context("SECTION relocation target symbol has no section")?;
                    write_u16(
                        buf,
                        file_offset,
                        crate::pe_layout::section_symbol_index(
                            layout,
                            contribution.object_index,
                            section_id,
                        )?,
                    )?;
                }
                InputRelocationTarget::Absolute => write_u16(buf, file_offset, 0)?,
            },
            pe::IMAGE_REL_AMD64_SECREL => {
                let section_base = layout.image_base + u64::from(output_section.virtual_address);
                let section_offset = target_addr
                    .checked_sub(section_base)
                    .context("SECREL target is below output section base")?;
                write_u32(buf, file_offset, checked_u32(section_offset, "SECREL")?)?;
            }
            typ => bail!(
                "unsupported COFF relocation type 0x{typ:04x} in `{}` section `{}`",
                layout.objects[contribution.object_index].path.display(),
                String::from_utf8_lossy(&input_section.name)
            ),
        }
    }

    Ok(())
}

fn write_rel32(
    buf: &mut [u8],
    file_offset: usize,
    target_addr: u64,
    reloc_va: u64,
    instruction_adjust: i128,
) -> Result {
    let value = i128::from(target_addr) - i128::from(reloc_va) - instruction_adjust;
    let value: i32 = value
        .try_into()
        .context("REL32 relocation target is out of range")?;
    write_i32(buf, file_offset, value)
}

fn checked_u32(value: u64, relocation_name: &str) -> Result<u32> {
    value
        .try_into()
        .with_context(|| format!("{relocation_name} relocation value 0x{value:x} overflows u32"))
}

fn write_u16(buf: &mut [u8], offset: usize, value: u16) -> Result {
    let bytes = buf
        .get_mut(offset..offset + 2)
        .context("relocation write out of bounds (u16)")?;
    bytes.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_u32(buf: &mut [u8], offset: usize, value: u32) -> Result {
    let bytes = buf
        .get_mut(offset..offset + 4)
        .context("relocation write out of bounds (u32)")?;
    bytes.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_i32(buf: &mut [u8], offset: usize, value: i32) -> Result {
    let bytes = buf
        .get_mut(offset..offset + 4)
        .context("relocation write out of bounds (i32)")?;
    bytes.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_u64(buf: &mut [u8], offset: usize, value: u64) -> Result {
    let bytes = buf
        .get_mut(offset..offset + 8)
        .context("relocation write out of bounds (u64)")?;
    bytes.copy_from_slice(&value.to_le_bytes());
    Ok(())
}
