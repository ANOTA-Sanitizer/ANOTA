use aya::{
    programs::{ProgramError, TracePoint},
    Bpf,
};

pub(super) fn load_and_attatch_enter_execve(bpf: &mut Bpf) -> Result<(), ProgramError> {
    let program: &mut TracePoint = bpf.program_mut("enter_execve").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_execve")?;
    return Ok(());
}