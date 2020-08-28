// Trying to read mem varible of pdb generated via
// rustc -g -Copt-level=2 .\hello.rs

use pdb::FallibleIterator;
use std::collections::HashMap;
use std::ffi::OsString;
use std::{fs::File, mem};
use winapi::shared::basetsd;
use winapi::shared::minwindef;
use winapi::shared::minwindef::FALSE;
use winapi::um::debugapi;
use winapi::um::fileapi;
use winapi::um::memoryapi::ReadProcessMemory;
use winapi::um::minwinbase;
use winapi::um::processthreadsapi::{
    CreateProcessW, GetThreadId, PROCESS_INFORMATION, STARTUPINFOW,
};
use winapi::um::winbase;
use winapi::um::winnt;

macro_rules! wide_string {
    ($string:expr) => {{
        use std::os::windows::ffi::OsStrExt;
        let input = std::ffi::OsStr::new($string);
        let vec: Vec<u16> = input.encode_wide().chain(Some(0)).collect();
        vec
    }};
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut symbol_map: HashMap<String, pdb::DataSymbol> = HashMap::new();
    //let pdb = "C:\\Users\\DeltaManiac\\git\\rust\\headcrab\\tests\\testees\\hello.pdb";
    let pdb = "C:\\Users\\DeltaManiac\\git\\rust\\testdb\\tests\\hello.pdb";
    //Load PDB and find STATICVAR
    let file = File::open(pdb)?;
    let mut pdb = pdb::PDB::open(file)?;
    let symbol_table = pdb.global_symbols()?;
    let address_map = pdb.address_map()?;
    fill_symbols(symbol_table.iter(), &mut symbol_map)?;
    dbg!(symbol_map.get("STATICVAR"));
    let path = "C:\\Users\\DeltaManiac\\git\\rust\\testdb\\tests\\hello.exe";
    let startup_info = mem::MaybeUninit::<STARTUPINFOW>::zeroed();
    let mut startup_info = unsafe { startup_info.assume_init() };
    let proc_info = mem::MaybeUninit::<PROCESS_INFORMATION>::zeroed();
    let mut proc_info = unsafe { proc_info.assume_init() };
    if unsafe {
        CreateProcessW(
            std::ptr::null_mut(),
            wide_string!(&path).as_mut_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            FALSE,
            winbase::DEBUG_ONLY_THIS_PROCESS,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut startup_info,
            &mut proc_info,
        )
    } == FALSE
    {
        return Err(Box::new(std::io::Error::last_os_error()));
    };
    let mut debug_event: minwinbase::DEBUG_EVENT = unsafe { mem::zeroed() };
    loop {
        if unsafe { debugapi::WaitForDebugEvent(&mut debug_event, winbase::INFINITE) } == FALSE {
            break;
        }
        match debug_event.dwDebugEventCode {
            minwinbase::CREATE_PROCESS_DEBUG_EVENT => {
                dbg!("Create Process");
            }
            minwinbase::LOAD_DLL_DEBUG_EVENT => {
                let dll_info = unsafe { debug_event.u.LoadDll() };
                if dll_info.hFile != std::ptr::null_mut() {
                    // Ask for the buffer size
                    let required_size = unsafe {
                        fileapi::GetFinalPathNameByHandleW(
                            dll_info.hFile,
                            std::ptr::null_mut(),
                            0,
                            0,
                        )
                    };
                    if required_size == 0 {
                        return Err(Box::new(std::io::Error::last_os_error()));
                    }
                    let mut buffer = vec![0u16; required_size as usize];
                    let written_size = unsafe {
                        fileapi::GetFinalPathNameByHandleW(
                            dll_info.hFile,
                            buffer.as_mut_ptr(),
                            required_size,
                            0,
                        )
                    };
                    if written_size == 0 || written_size > required_size {
                        return Err(Box::new(std::io::Error::last_os_error()));
                    }
                    // Remove 0-terminator
                    let buffer = &buffer[..(written_size as usize)];
                    use std::os::windows::ffi::OsStringExt;
                    let d: String = OsString::from_wide(buffer).into_string().unwrap();
                    println!(
                        "=============Loaded Module: {0}=============",
                        d.as_str().split('\\').last().unwrap()
                    );
                }
            }
            minwinbase::UNLOAD_DLL_DEBUG_EVENT => {
                dbg!("Unload DLL");
            }
            minwinbase::CREATE_THREAD_DEBUG_EVENT => {
                dbg!("Create Thread");
                let thread_info = unsafe { debug_event.u.CreateThread() };
                dbg!(unsafe { GetThreadId(thread_info.hThread) });
                // let mut buf = [0u16; 1024];
                let mut buf = [0u8; 14];
                unsafe {
                    ReadProcessMemory(
                        proc_info.hProcess,
                        (thread_info.lpStartAddress.unwrap() as usize + 0x340 as usize)
                            as minwindef::LPVOID,
                        buf.as_mut_ptr() as minwindef::LPVOID,
                        buf.len() as basetsd::SIZE_T,
                        std::ptr::null_mut(),
                    )
                };
                // let d = unsafe { String::from_utf16_lossy(&buf) };
                let d = { String::from_utf8_lossy(&buf) };
                dbg!(d);
            }
            minwinbase::EXIT_THREAD_DEBUG_EVENT => {
                dbg!("Exit Thread");
            }
            minwinbase::EXCEPTION_DEBUG_EVENT => {
                dbg!("Execption");
            }
            minwinbase::EXIT_PROCESS_DEBUG_EVENT => {
                dbg!("Exit Process");
                break;
            }
            minwinbase::RIP_EVENT => {
                dbg!("RIP");
            }
            _ => {}
        }
        unsafe {
            debugapi::ContinueDebugEvent(
                debug_event.dwProcessId,
                debug_event.dwThreadId,
                winnt::DBG_CONTINUE,
            )
        };
    }
    Ok(())
}
fn find_symbol<'t>(
    symbol: &pdb::Symbol<'t>,
    map: &mut HashMap<String, pdb::DataSymbol<'t>>,
) -> pdb::Result<()> {
    match symbol.parse()? {
        pdb::SymbolData::Data(data) => {
            map.insert(data.name.to_string().to_string().clone(), data.clone());
        }
        _ => {
            // ignore everything else
        }
    }
    Ok(())
}

fn fill_symbols<'t>(
    mut symbols: pdb::SymbolIter<'t>,
    map: &mut HashMap<String, pdb::DataSymbol<'t>>,
) -> pdb::Result<()> {
    let g = while let Some(symbol) = symbols.next()? {
        let sym = match find_symbol(&symbol, map) {
            Ok(_) => {}
            Err(e) => {}
        };
    };
    Ok(())
}
