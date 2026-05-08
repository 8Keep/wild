//! PE/COFF linking pipeline orchestration.

use crate::arch::Architecture;
use crate::args::pe::PeArgs;
use crate::bail;
use crate::error::Context as _;
use crate::error::Result;

pub(crate) fn link_pe(_linker: &crate::Linker, args: &PeArgs) -> Result {
    if args.arch != Architecture::X86_64 {
        bail!(
            "PE/COFF linking currently only supports x86_64; requested {}",
            args.arch
        );
    }

    let inputs = crate::pe_object::load_input_objects(args)?;
    if inputs.is_empty() {
        bail!("no COFF object inputs");
    }

    let mut layout = crate::pe_layout::compute_layout(args, inputs)?;
    crate::pe_layout::resolve_symbols(&mut layout)?;
    layout.entry_point_rva = crate::pe_layout::find_entry_point_rva(args, &layout)?;

    let output = crate::pe_writer::write_image(args, &layout)?;

    if let Some(parent) = args.output.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create output directory `{}`", parent.display()))?;
    }
    std::fs::write(args.output.as_ref(), output)
        .with_context(|| format!("failed to write PE output `{}`", args.output.display()))?;

    Ok(())
}
