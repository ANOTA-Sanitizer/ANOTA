use aya::{
    programs::{ProgramError, TracePoint},
    Bpf,
};

pub(super) fn load_and_attatch_enter_access(bpf: &mut Bpf) -> Result<(), ProgramError> {
    let program: &mut TracePoint = bpf.program_mut("enter_access").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_access")?;
    return Ok(());
}

pub(super) fn load_and_attatch_enter_open(bpf: &mut Bpf) -> Result<(), ProgramError> {
    let program: &mut TracePoint = bpf.program_mut("enter_open").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_open")?;
    return Ok(());
}

pub(super) fn load_and_attatch_exit_open(bpf: &mut Bpf) -> Result<(), ProgramError> {
    let program: &mut TracePoint = bpf.program_mut("exit_open").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_exit_open")?;
    return Ok(());
}

pub(super) fn load_and_attatch_enter_openat(bpf: &mut Bpf) -> Result<(), ProgramError> {
    let program: &mut TracePoint = bpf.program_mut("enter_openat").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_openat")?;
    return Ok(());
}

pub(super) fn load_and_attatch_exit_openat(bpf: &mut Bpf) -> Result<(), ProgramError> {
    let program: &mut TracePoint = bpf.program_mut("exit_openat").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_exit_openat")?;
    return Ok(());
}

pub(super) fn load_and_attatch_enter_openat2(bpf: &mut Bpf) -> Result<(), ProgramError> {
    let program: &mut TracePoint = bpf.program_mut("enter_openat2").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_openat2")?;
    return Ok(());
}

pub(super) fn load_and_attatch_enter_write(bpf: &mut Bpf) -> Result<(), ProgramError> {
    let program: &mut TracePoint = bpf.program_mut("enter_write").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_write")?;
    return Ok(());
}

pub(super) fn load_and_attatch_enter_read(bpf: &mut Bpf) -> Result<(), ProgramError> {
    let program: &mut TracePoint = bpf.program_mut("enter_read").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_read")?;
    return Ok(());
}