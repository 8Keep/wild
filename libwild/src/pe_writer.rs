//! PE executable output writing.

use crate::args::pe::PeArgs;
use crate::args::pe::WindowsSubsystem;
use crate::bail;
use crate::error::Context as _;
use crate::error::Result;
use crate::pe_layout::FILE_ALIGNMENT;
use crate::pe_layout::PeLayout;
use crate::pe_layout::SECTION_ALIGNMENT;
use object::LittleEndian as LE;
use object::pe;

const DOS_HEADER_SIZE: u32 = core::mem::size_of::<pe::ImageDosHeader>() as u32;
const PE_SIGNATURE_SIZE: u32 = 4;
const COFF_HEADER_SIZE: u32 = core::mem::size_of::<pe::ImageFileHeader>() as u32;
const OPTIONAL_HEADER_BASE_SIZE: u32 = core::mem::size_of::<pe::ImageOptionalHeader64>() as u32;
const DATA_DIRS_SIZE: u32 = pe::IMAGE_NUMBEROF_DIRECTORY_ENTRIES as u32
    * core::mem::size_of::<pe::ImageDataDirectory>() as u32;
const OPTIONAL_HEADER_SIZE: u32 = OPTIONAL_HEADER_BASE_SIZE + DATA_DIRS_SIZE;
const SECTION_HEADER_SIZE: u32 = core::mem::size_of::<pe::ImageSectionHeader>() as u32;

pub(crate) fn headers_size(num_sections: usize) -> u32 {
    DOS_HEADER_SIZE
        + PE_SIGNATURE_SIZE
        + COFF_HEADER_SIZE
        + OPTIONAL_HEADER_SIZE
        + SECTION_HEADER_SIZE * num_sections as u32
}

pub(crate) fn write_image(args: &PeArgs, layout: &PeLayout) -> Result<Vec<u8>> {
    let mut output = vec![0; layout.file_size as usize];
    write_headers(&mut output, args, layout)?;
    write_sections(&mut output, layout)?;
    Ok(output)
}

fn write_headers(buf: &mut [u8], args: &PeArgs, layout: &PeLayout) -> Result {
    let e = LE;
    let mut offset = 0usize;

    let dos_header: &mut pe::ImageDosHeader = from_bytes_mut_at(buf, &mut offset)?;
    dos_header.e_magic.set(e, pe::IMAGE_DOS_SIGNATURE);
    dos_header.e_lfanew.set(e, DOS_HEADER_SIZE);

    buf.get_mut(offset..offset + 4)
        .context("buffer too small for PE signature")?
        .copy_from_slice(&pe::IMAGE_NT_SIGNATURE.to_le_bytes());
    offset += 4;

    let file_header: &mut pe::ImageFileHeader = from_bytes_mut_at(buf, &mut offset)?;
    file_header.machine.set(e, layout.machine);
    file_header
        .number_of_sections
        .set(e, layout.sections.len() as u16);
    file_header.time_date_stamp.set(e, 0);
    file_header.pointer_to_symbol_table.set(e, 0);
    file_header.number_of_symbols.set(e, 0);
    file_header
        .size_of_optional_header
        .set(e, OPTIONAL_HEADER_SIZE as u16);
    let mut characteristics = pe::IMAGE_FILE_EXECUTABLE_IMAGE;
    if args.large_address_aware {
        characteristics |= pe::IMAGE_FILE_LARGE_ADDRESS_AWARE;
    }
    if args.is_dll {
        characteristics |= pe::IMAGE_FILE_DLL;
    }
    file_header.characteristics.set(e, characteristics);

    let opt_header: &mut pe::ImageOptionalHeader64 = from_bytes_mut_at(buf, &mut offset)?;
    opt_header.magic.set(e, pe::IMAGE_NT_OPTIONAL_HDR64_MAGIC);
    opt_header.major_linker_version = 1;
    opt_header.minor_linker_version = 0;
    opt_header
        .address_of_entry_point
        .set(e, layout.entry_point_rva);
    opt_header.image_base.set(e, layout.image_base);
    opt_header.section_alignment.set(e, SECTION_ALIGNMENT);
    opt_header.file_alignment.set(e, FILE_ALIGNMENT);
    opt_header.major_operating_system_version.set(e, 6);
    opt_header.minor_operating_system_version.set(e, 0);
    opt_header.major_subsystem_version.set(e, 6);
    opt_header.minor_subsystem_version.set(e, 0);
    opt_header.size_of_image.set(e, layout.size_of_image);
    opt_header.size_of_headers.set(e, layout.size_of_headers);
    opt_header.subsystem.set(e, subsystem(args.subsystem));
    opt_header
        .dll_characteristics
        .set(e, dll_characteristics(args));
    opt_header
        .size_of_stack_reserve
        .set(e, args.stack_size.unwrap_or(0x100000));
    opt_header.size_of_stack_commit.set(e, 0x1000);
    opt_header
        .size_of_heap_reserve
        .set(e, args.heap_size.unwrap_or(0x100000));
    opt_header.size_of_heap_commit.set(e, 0x1000);
    opt_header
        .number_of_rva_and_sizes
        .set(e, pe::IMAGE_NUMBEROF_DIRECTORY_ENTRIES as u32);

    let mut size_of_code = 0u32;
    let mut size_of_initialized_data = 0u32;
    let mut size_of_uninitialized_data = 0u32;
    let mut base_of_code = 0u32;
    for section in &layout.sections {
        if section.characteristics & pe::IMAGE_SCN_CNT_CODE != 0 {
            size_of_code += section.raw_data_size;
            if base_of_code == 0 {
                base_of_code = section.virtual_address;
            }
        }
        if section.characteristics & pe::IMAGE_SCN_CNT_INITIALIZED_DATA != 0 {
            size_of_initialized_data += section.raw_data_size;
        }
        if section.characteristics & pe::IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0 {
            size_of_uninitialized_data += section.virtual_size;
        }
    }
    opt_header.size_of_code.set(e, size_of_code);
    opt_header
        .size_of_initialized_data
        .set(e, size_of_initialized_data);
    opt_header
        .size_of_uninitialized_data
        .set(e, size_of_uninitialized_data);
    opt_header.base_of_code.set(e, base_of_code);

    buf.get_mut(offset..offset + DATA_DIRS_SIZE as usize)
        .context("buffer too small for PE data directories")?
        .fill(0);
    offset += DATA_DIRS_SIZE as usize;

    for section in &layout.sections {
        let section_header: &mut pe::ImageSectionHeader = from_bytes_mut_at(buf, &mut offset)?;
        section_header.name = section.name;
        section_header.virtual_size.set(e, section.virtual_size);
        section_header
            .virtual_address
            .set(e, section.virtual_address);
        section_header.size_of_raw_data.set(
            e,
            if section.is_bss {
                0
            } else {
                section.raw_data_size
            },
        );
        section_header
            .pointer_to_raw_data
            .set(e, section.file_offset);
        section_header.pointer_to_relocations.set(e, 0);
        section_header.pointer_to_linenumbers.set(e, 0);
        section_header.number_of_relocations.set(e, 0);
        section_header.number_of_linenumbers.set(e, 0);
        section_header
            .characteristics
            .set(e, section.characteristics);
    }

    Ok(())
}

fn write_sections(buf: &mut [u8], layout: &PeLayout) -> Result {
    for section in &layout.sections {
        if section.is_bss {
            continue;
        }
        for contribution in &section.contributions {
            let object = &layout.objects[contribution.object_index];
            let input_section = &object.sections[contribution.section_index];
            let out_offset = section.file_offset as usize + contribution.output_offset as usize;
            let copy_size = input_section.data.len().min(contribution.size as usize);
            buf.get_mut(out_offset..out_offset + copy_size)
                .with_context(|| {
                    format!(
                        "section `{}` write out of bounds",
                        String::from_utf8_lossy(&input_section.name)
                    )
                })?
                .copy_from_slice(&input_section.data[..copy_size]);

            crate::pe_reloc::apply_relocations(buf, layout, section, contribution, input_section)?;
        }
    }

    Ok(())
}

fn subsystem(subsystem: Option<WindowsSubsystem>) -> u16 {
    match subsystem.unwrap_or(WindowsSubsystem::Console) {
        WindowsSubsystem::Console => pe::IMAGE_SUBSYSTEM_WINDOWS_CUI,
        WindowsSubsystem::Windows => pe::IMAGE_SUBSYSTEM_WINDOWS_GUI,
        WindowsSubsystem::Native => pe::IMAGE_SUBSYSTEM_NATIVE,
        WindowsSubsystem::Posix => pe::IMAGE_SUBSYSTEM_POSIX_CUI,
        WindowsSubsystem::BootApplication => pe::IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION,
        WindowsSubsystem::EfiApplication => pe::IMAGE_SUBSYSTEM_EFI_APPLICATION,
        WindowsSubsystem::EfiBootServiceDriver => pe::IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER,
        WindowsSubsystem::EfiRom => pe::IMAGE_SUBSYSTEM_EFI_ROM,
        WindowsSubsystem::EfiRuntimeDriver => pe::IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER,
    }
}

fn dll_characteristics(args: &PeArgs) -> u16 {
    let mut flags = 0;
    if args.high_entropy_va {
        flags |= pe::IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA;
    }
    if args.dynamic_base {
        flags |= pe::IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
    }
    if args.nx_compat {
        flags |= pe::IMAGE_DLLCHARACTERISTICS_NX_COMPAT;
    }
    if args.terminal_server_aware {
        flags |= pe::IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE;
    }
    flags
}

fn from_bytes_mut_at<'a, T: object::pod::Pod>(
    buf: &'a mut [u8],
    offset: &mut usize,
) -> Result<&'a mut T> {
    let size = core::mem::size_of::<T>();
    let end = *offset + size;
    if end > buf.len() {
        bail!("buffer too small: need {end} bytes, have {}", buf.len());
    }
    let slice = &mut buf[*offset..end];
    let ptr = slice.as_mut_ptr() as *mut T;
    *offset = end;
    Ok(unsafe { &mut *ptr })
}
