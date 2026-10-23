#![no_std]

pub mod syscalls;

pub const PATH_LEN: usize = 4096;
pub const EVENT_SYSCALL: u32 = 1;
pub const EVENT_FORK: u32 = 2;
pub const EVENT_EXIT: u32 = 3;
pub const CAPTURE_ERROR: u32 = 1;
pub const PATH_TRUNCATED: u32 = 2;
pub const AT_FDCWD: i32 = -100;

/// Fixed wire layout shared by the kernel and userspace. No pointers or padding.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Event {
    pub session: u64,
    pub generation: u64,
    pub syscall: u64,
    pub result: i64,
    pub args: [u64; 6],
    pub pid: u32,
    pub tid: u32,
    pub kind: u32,
    pub flags: u32,
    pub path_len: [u32; 2],
    pub address_len: u32,
    pub reserved: u32,
    pub paths: [[u8; PATH_LEN]; 2],
    pub address: [u8; 128],
}

impl Event {
    pub const fn empty() -> Self {
        Self {
            session: 0,
            generation: 0,
            syscall: 0,
            result: 0,
            args: [0; 6],
            pid: 0,
            tid: 0,
            kind: 0,
            flags: 0,
            path_len: [0; 2],
            address_len: 0,
            reserved: 0,
            paths: [[0; PATH_LEN]; 2],
            address: [0; 128],
        }
    }
}

/// Path argument index and optional dirfd argument index (-1 means cwd).
/// A second path is independently checked for rename/link operations.
pub fn path_arguments(nr: u64) -> [(i32, i32); 2] {
    match nr {
        2 | 4 | 6 | 21 | 59 | 76 | 80 | 83 | 84 | 87 | 89 | 90 | 92 | 94 | 132 | 133 | 137
        | 188 | 189 | 191 | 192 | 194 | 195 | 197 | 198 | 235 => [(0, -1), (-1, -1)],
        82 | 86 => [(0, -1), (1, -1)],
        // A symlink target is data; the new link's pathname is the operation.
        88 => [(1, -1), (-1, -1)],
        257 | 258 | 259 | 260 | 261 | 262 | 263 | 267 | 268 | 269 | 280 | 322 | 332 | 437 | 439
        | 452 => [(1, 0), (-1, -1)],
        264 | 265 | 316 => [(1, 0), (3, 2)],
        266 => [(2, 1), (-1, -1)],
        _ => [(-1, -1); 2],
    }
}

pub fn is_read(nr: u64) -> bool {
    matches!(
        nr,
        0 | 17 | 19 | 40 | 78 | 89 | 187 | 217 | 267 | 275 | 295 | 326 | 327
    )
}

pub fn is_write(nr: u64) -> bool {
    matches!(
        nr,
        1 | 18 | 20 | 40 | 76 | 77 | 275 | 276 | 278 | 285 | 296 | 326 | 328
    )
}

pub fn is_network(nr: u64) -> bool {
    matches!(nr, 41..=55 | 288 | 299 | 307)
}

pub fn fd_argument(nr: u64) -> Option<usize> {
    match nr {
        0
        | 1
        | 3
        | 5
        | 8
        | 16
        | 17
        | 18
        | 19
        | 20
        | 32
        | 33
        | 42..=55
        | 72
        | 73
        | 74
        | 75
        | 77
        | 78
        | 81
        | 91
        | 93
        | 138
        | 187
        | 190
        | 193
        | 196
        | 199
        | 217
        | 221
        | 275
        | 276
        | 277
        | 278
        | 285
        | 288
        | 292
        | 295
        | 296
        | 299
        | 307
        | 326
        | 327
        | 328
        | 451 => Some(0),
        9 => Some(4),  // mmap
        40 => Some(1), // sendfile input
        _ => None,
    }
}

pub fn syscall_name(nr: u64) -> Option<&'static str> {
    syscalls::NAMES
        .iter()
        .find(|(number, _)| *number == nr)
        .map(|(_, name)| *name)
}
