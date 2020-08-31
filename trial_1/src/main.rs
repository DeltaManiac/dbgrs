#[cfg(windows)]
extern crate winapi;
use std::mem;
use std::os::windows::prelude::*;
use winapi::shared::basetsd::DWORD64;
use winapi::shared::basetsd::SIZE_T;
use winapi::shared::minwindef::BOOL;
use winapi::shared::minwindef::DWORD;
use winapi::shared::minwindef::FALSE;
use winapi::shared::minwindef::LPVOID;
use winapi::shared::minwindef::ULONG;
use winapi::shared::ntdef::WCHAR;
use winapi::um::dbghelp::SymFromNameW;
use winapi::um::dbghelp::SymGetOptions;
use winapi::um::dbghelp::SymInitializeW;
use winapi::um::dbghelp::SymLoadModuleExW;
use winapi::um::dbghelp::SymSetOptions;
use winapi::um::dbghelp::MAX_SYM_NAME;
use winapi::um::dbghelp::SYMBOL_INFOW;
use winapi::um::dbghelp::SYMOPT_DEBUG;
use winapi::um::dbghelp::SYMOPT_LOAD_LINES;
use winapi::um::debugapi::ContinueDebugEvent;
use winapi::um::debugapi::WaitForDebugEvent;
use winapi::um::debugapi::WaitForDebugEventEx;
use winapi::um::fileapi::FILE_BASIC_INFO;
use winapi::um::fileapi::FILE_NAME_INFO;
use winapi::um::fileapi::FILE_STANDARD_INFO;
use winapi::um::memoryapi::ReadProcessMemory;
use winapi::um::minwinbase::CREATE_PROCESS_DEBUG_EVENT;
use winapi::um::minwinbase::CREATE_THREAD_DEBUG_EVENT;
use winapi::um::minwinbase::DEBUG_EVENT;
use winapi::um::minwinbase::EXCEPTION_DEBUG_EVENT;
use winapi::um::minwinbase::EXIT_PROCESS_DEBUG_EVENT;
use winapi::um::minwinbase::EXIT_THREAD_DEBUG_EVENT;
use winapi::um::minwinbase::LOAD_DLL_DEBUG_EVENT;
use winapi::um::minwinbase::LPCONTEXT;
use winapi::um::processthreadsapi::{
    CreateProcessW, GetThreadContext, PROCESS_INFORMATION, STARTUPINFOW,
};
use winapi::um::winbase::GetFileInformationByHandleEx;
use winapi::um::winbase::DEBUG_ONLY_THIS_PROCESS;
use winapi::um::winbase::INFINITE;
use winapi::um::winnt::CONTEXT;
use winapi::um::winnt::CONTEXT_ALL;
use winapi::um::winnt::DBG_CONTINUE;


use pdb::{AddressMap, FallibleIterator, PdbInternalSectionOffset};
use std::collections::HashMap;
use std::os::windows::ffi::OsStringExt;

fn main() {
    let win = "C:\\Users\\DeltaManiac\\git\\rust\\headcrab\\tests\\testees\\hello.exe";
    // let win = "hello.exe";
    let win1 = "C:\\Users\\DeltaManiac\\git\\rust\\headcrab\\tests\\testees\\hello.pdb";
    let mut lp_cmd_name = string_to_wide_string(win.to_string());
    // let lp_cmd_name = std::ffi::OsStr::new(win.clone())
    //     .encode_wide()
    //     .chain(std::iter::once(0))
    //     .collect();
    let sym_opts = unsafe { SymGetOptions() };
    dbg!(sym_opts);
    unsafe { SymSetOptions(sym_opts | SYMOPT_DEBUG | SYMOPT_LOAD_LINES) };
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
    let res = unsafe { SymInitializeW(pi.hProcess, std::ptr::null(), FALSE) };
    dbg!(res);
    unsafe { dbg!(winapi::um::errhandlingapi::GetLastError()) };
    dbg!(&pi.dwThreadId);
    dbg!(&pi.dwProcessId);
    let mut debug_event: DEBUG_EVENT = unsafe { mem::zeroed() };

    //////////////////////
    let file = std::fs::File::open(win1).unwrap();
    let mut pdb = pdb::PDB::open(file).unwrap();
    let symbol_table = pdb.global_symbols().unwrap();
    // let address_map = pdb.address_map().unwrap();
    // let dbi = pdb.debug_information().unwrap();
    //    let sym = find_symbol(symbol_table);
    //   dbg!(sym);
    ////////////////////////////////////////O
    loop {
        let c = unsafe { WaitForDebugEvent(&mut debug_event, INFINITE) };
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
                    let ok = SymLoadModuleExW(
                        pi.hProcess,
                        proc_info.hFile,
                        std::ptr::null(),
                        std::ptr::null(),
                        proc_info.lpBaseOfImage as DWORD64,
                        0,
                        std::ptr::null_mut(),
                        0,
                    );
                    dbg!(ok);
                    unsafe { dbg!(winapi::um::errhandlingapi::GetLastError()) };
                    GetThreadContext(proc_info.hThread, &mut context as LPCONTEXT);
                    dbg!(context.Rip);

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
                    let mut symbol = SYMBOL_INFOW {
                        SizeOfStruct: std::mem::size_of::<SYMBOL_INFOW>() as ULONG,
                        ..std::mem::zeroed()
                    };
                    let name: Vec<u16> = "STATICVAR2\0".encode_utf16().collect();
                    let name2: Vec<u16> = std::ffi::OsStr::new("STATICVAR")
                        .encode_wide()
                        .chain(Some(0))
                        .collect();
                    let g = SymFromNameW(pi.hProcess, name2.as_ptr(), &mut symbol);
                    dbg!(g);
                    dbg!(symbol.Address);
                    dbg!(winapi::um::errhandlingapi::GetLastError());
                    let addr = proc_info.lpBaseOfImage as usize;
                    // ReadProcessMemory(
                    //     pi.hProcess,
                    //     context.Rbp as usize + symbol.Address as usize as LPVOID,
                    //     buf.as_mut_ptr() as LPVOID,
                    //     buf.len() as SIZE_T,
                    //     std::ptr::null_mut(),
                    // );
                    // dbg!(buf);
                    let d = String::from_utf16(&buf);
                    dbg!(d);
                };

                //Read Mem
            }
            LOAD_DLL_DEBUG_EVENT => {
                // debug_event.loadDll();
                dbg!("Loaded DLL EVENT");

                let mut buf = [0u16; 1024];
                // let mut buf = [0u8; 1024];
                // let ret = unsafe {
                //     GetFileInformationByHandleEx(
                //         debug_event.u.LoadDll().hFile,
                //         winapi::um::minwinbase::FileStandardInfo,
                //         buf.as_mut_ptr() as *mut _,
                //         buf.len() as u32,
                //     )
                // };
                unsafe {
                    ReadProcessMemory(
                        pi.hProcess,
                        (debug_event.u.LoadDll().lpBaseOfDll as usize + 0x1d340 as usize) as LPVOID,
                        buf.as_mut_ptr() as LPVOID,
                        buf.len() as SIZE_T,
                        std::ptr::null_mut(),
                    )
                };
                // dbg!(buf);

                let d = unsafe { String::from_utf16_lossy(&buf) };
                // let d = unsafe { String::from_utf8_lossy(&buf) };
                dbg!(d);
                // unsafe {
                //                     let info = std::ptr::NonNull::new_unchecked(buf.as_mut_ptr()).cast::<FILE_NAME_INFO>();
                //                     let info = info.as_ref();
                //                     let filename = std::slice::from_raw_parts(
                //                         info.FileName.as_ptr(),
                //                         (info.FileNameLength as usize) / mem::size_of::<WCHAR>(),
                //                     );

                //                     dbg!(std::path::PathBuf::from(std::ffi::OsString::from_wide(filename)));
                // }
                let mut info = unsafe { std::mem::zeroed::<FILE_NAME_INFO>() };

                let class = winapi::um::minwinbase::FileStandardInfo;
                let data = &mut info as *mut _ as *mut _;
                let size = std::mem::size_of::<FILE_NAME_INFO>() as DWORD;
                let k = unsafe {
                    GetFileInformationByHandleEx(debug_event.u.LoadDll().hFile, class, data, size)
                };

                dbg!(info.FileName);
                // unsafe { dbg!(winapi::um::errhandlingapi::GetLastError()) };
            }
            CREATE_THREAD_DEBUG_EVENT => {
                dbg!("Create Thread debug EVENT");
            }
            EXIT_THREAD_DEBUG_EVENT => {
                dbg!("Exit Thread debug EVENT");
            }
            EXCEPTION_DEBUG_EVENT => {
                let exception = unsafe { debug_event.u.Exception() };
                match exception.ExceptionRecord.ExceptionCode {
                    winapi::um::minwinbase::EXCEPTION_BREAKPOINT => {
                        dbg!("Breakpoint Exception");
                    }
                    _ => {
                        dbg!("oter Exceptions");
                    }
                }
                unsafe { dbg!(debug_event.u.Exception().ExceptionRecord.ExceptionCode) };
            }

            EXIT_PROCESS_DEBUG_EVENT => {
                dbg!("Exit Process debug EVENT");
                break;
            }
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

fn find_symbol<'t>(
    symbol: &pdb::Symbol<'t>,
    am: &AddressMap,
    map: &mut HashMap<String, pdb::DataSymbol<'t>>,
) -> pdb::Result<()> {
    match symbol.parse()? {
    // This statement fails
        pdb::SymbolData::Data(data) => {
            map.insert(
                data.name.to_string().to_string().clone(),
                data.clone()
            );
        }
        _ => {
            // ignore everything else
        }
    }
    Ok(())
}

fn walk_symbols<'t>(
    mut symbols: pdb::SymbolIter<'t>,
    address_map: &AddressMap,
    map: &mut  HashMap<String,pdb::DataSymbol<'t>>
) -> pdb::Result<()> {
    let g = while let Some(symbol) = symbols.next()? {
        let sym = match find_symbol(&symbol, address_map, map) {
            Ok(_) => {}
            Err(e) =>{}, 
        };
    };
    Ok(())
}

// fn find_symbol(symbol_table: pdb::SymbolTable) -> Option<&pdb::DataSymbol> {
//     // symbol_table.find(|s| if s.parse().unwrap() == pd)
//     // for symbol in symbol_tablGe.iter(){
//     while let Some(symbol) = &symbol_table.iter().next().unwrap() {
//         dbg!(symbol);
//         let c = match symbol.parse() {
//             Ok(pdb::SymbolData::Data(data)) => {
//                 if data.name.to_string() == "STATICVAR" {
//                     Some(&data)
//                 } else {
//                     continue;
//                 }
//             }
//             Ok(_) => None,
//             Err(e) => None,
//         };
//         if c.is_some() {
//             let var_name = c;
//             return var_name;
//         }
//         // match symbol.parse().unwrap() {
//         //     pdb::SymbolData::Data(data) => {
//         //         dbg!(data.name);
//         //         if data.name.to_string() == "STATICVAR" {
//         //             return Some(data.to_owned());
//         //         } else{
//         //             continue;
//         //         }
//         //     }
//         //     _ => {}
//         // }
//     }
//     None
// }
