#[cfg(windows)]
extern crate winapi;
use std::mem;
use std::os::windows::prelude::*;
use winapi::shared::basetsd::SIZE_T;
use winapi::shared::minwindef::BOOL;
use winapi::shared::minwindef::LPVOID;
use winapi::um::dbghelp::SymFromNameW;
use winapi::um::dbghelp::SymInitializeW;
use winapi::um::dbghelp::MAX_SYM_NAME;
use winapi::um::dbghelp::SYMBOL_INFOW;
use winapi::um::debugapi::ContinueDebugEvent;
use winapi::um::debugapi::WaitForDebugEventEx;
use winapi::um::memoryapi::ReadProcessMemory;
use winapi::um::minwinbase::CREATE_PROCESS_DEBUG_EVENT;
use winapi::um::minwinbase::DEBUG_EVENT;
use winapi::um::minwinbase::EXIT_PROCESS_DEBUG_EVENT;
use winapi::um::minwinbase::LPCONTEXT;
use winapi::shared::ntdef::WCHAR;
use winapi::um::processthreadsapi::{
    CreateProcessW, GetThreadContext, PROCESS_INFORMATION, STARTUPINFOW,
};
use winapi::um::winbase::DEBUG_ONLY_THIS_PROCESS;
use winapi::um::winbase::INFINITE;
use winapi::um::winnt::CONTEXT;
use winapi::um::winnt::CONTEXT_ALL;
use winapi::um::winnt::DBG_CONTINUE;
fn main() {
    let win = "C:\\Users\\DeltaManiac\\git\\rust\\win\\tests\\hello.exe";
    let win1 = "C:\\Users\\DeltaManiac\\git\\rust\\win\\tests\\hello.pdb";
    let mut lp_cmd_name = string_to_wide_string(win.to_string());
    // let lp_cmd_name = std::ffi::OsStr::new(win.clone())
    //     .encode_wide()
    //     .chain(std::iter::once(0))
    //     .collect();

    let mut si: STARTUPINFOW = unsafe { mem::zeroed() };
    let mut pi: PROCESS_INFORMATION = unsafe { mem::zeroed() };
    unsafe {
        CreateProcessW(
            std::ptr::null_mut(),
            lp_cmd_name.as_mut_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            false as BOOL,
            DEBUG_ONLY_THIS_PROCESS,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut si,
            &mut pi,
        );
    }
    dbg!(&pi.dwThreadId);
    dbg!(&pi.dwProcessId);
    let mut debug_event: DEBUG_EVENT = unsafe { mem::zeroed() };
    loop {
        let c = unsafe { WaitForDebugEventEx(&mut debug_event, INFINITE) };
        dbg!(&debug_event.dwDebugEventCode);
        if c == 0 {
            return;
        }
        match debug_event.dwDebugEventCode {
            CREATE_PROCESS_DEBUG_EVENT => {
                let mut context: CONTEXT = unsafe { mem::zeroed() };
                context.ContextFlags = CONTEXT_ALL;
                let mut buf: [u16; 13] = [0; 13];
                unsafe {
                    let proc_info = debug_event.u.CreateProcessInfo();
                    GetThreadContext(proc_info.hThread, &mut context as LPCONTEXT);
                    dbg!(context.Rip);
                    let bSuccess: BOOL =
                        SymInitializeW(proc_info.hProcess, std::ptr::null(), false as BOOL);

                    dbg!(bSuccess);
                    let mut buffer = vec![
                        0;
                        mem::size_of::<SYMBOL_INFOW>()
                            + MAX_SYM_NAME * mem::size_of::<WCHAR>()
                    ];
                    let info: &mut SYMBOL_INFOW = &mut *(buffer.as_mut_ptr() as *mut _);
                    info.SizeOfStruct = mem::size_of::<SYMBOL_INFOW>() as u32;
                    info.MaxNameLen = MAX_SYM_NAME as u32;
                    let name: Vec<u16> = "STATICVAR2\0".encode_utf16().collect();
                    let name2: Vec<u16> = std::ffi::OsStr::new("STATICVAR").encode_wide().chain(Some(0)).collect();
                    let g = SymFromNameW(proc_info.hProcess, name2.as_ptr(), info);
                    dbg!(g);
                    dbg!(info.Address);
                    let addr = proc_info.lpBaseOfImage as usize;
                    ReadProcessMemory(
                        proc_info.hProcess,
                        0x58a50 as LPVOID,
                        buf.as_mut_ptr() as LPVOID,
                        buf.len() as SIZE_T,
                        std::ptr::null_mut(),
                    );
                    // dbg!(buf);
                    let d = String::from_utf16(&buf);
                    // dbg!(d);
                };

                //Read Mem
            }
            EXIT_PROCESS_DEBUG_EVENT => break,
            _ => (),
        }
        unsafe {
            ContinueDebugEvent(
                debug_event.dwProcessId,
                debug_event.dwThreadId,
                DBG_CONTINUE,
            )
        };
    }
}

fn string_to_wide_string(input: String) -> Vec<u16> {
    let input = std::ffi::OsStr::new(&input);
    let vec: Vec<u16> = input.encode_wide().chain(Some(0)).collect();
    vec
}
