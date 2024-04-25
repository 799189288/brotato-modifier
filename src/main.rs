#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")] // hide console window on Windows in release
use std::{
    fmt::Debug,
    os::raw::c_void,
    ptr,
    sync::Arc,
    thread::{self, sleep},
    time::Duration,
};

use eframe::egui::{self, mutex::Mutex, DragValue, ViewportBuilder};
use tracing::{error, info, Level};
use tracing_subscriber::{fmt, FmtSubscriber};
use windows::{
    core::{s, PCSTR},
    Win32::{
        Foundation::{BOOL, HMODULE},
        System::{
            Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory},
            LibraryLoader::GetModuleHandleA,
            ProcessStatus::{EnumProcessModules, GetModuleInformation, MODULEINFO},
            Threading::{OpenProcess, PROCESS_ALL_ACCESS},
        },
        UI::WindowsAndMessaging::{FindWindowA, GetWindowThreadProcessId},
    },
};
const BASE_POINTER: u64 = 0x7FF714870000;
const OFFSET_LAST: u64 = 0x200;
const OFFSET_VEC: [u64; 6] = [0x025362D0, 0x148, 0x108, 0x38, 0x58, 0x20];

fn read_u64(base_ptr: u64, offset: u64, h_process: windows::Win32::Foundation::HANDLE) -> u64 {
    unsafe {
        let base_ptr = base_ptr + offset;
        let base_ptr_deref = [0u64; 1];
        // error!("{:?}", base_ptr_deref);
        ReadProcessMemory(
            h_process,
            base_ptr as *const c_void,
            base_ptr_deref.as_ptr() as *mut c_void,
            8,
            None,
        )
        .unwrap();

        let u64_ptr = base_ptr_deref[0] as *const u64;
        u64_ptr as u64
    }
}

fn main() -> () {
    let options = eframe::NativeOptions {
        viewport: ViewportBuilder::default()
            .with_min_inner_size([300.0, 200.0])
            .with_inner_size([250.0, 150.0]),
        ..Default::default()
    };
    let file_appender = tracing_appender::rolling::daily("./log", "prefix.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
    let subscriber = FmtSubscriber::builder()
        // all spans/events with a level higher than TRACE (e.g, debug, info, warn, etc.)
        // will be written to stdout.
        .with_writer(non_blocking)
        .with_max_level(Level::TRACE)
        .with_ansi(false)
        // completes the builder.
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");
    let _ = eframe::run_native(
        "土豆兄弟修改器",
        options,
        Box::new(|cc| Box::new(MyApp::new(cc))),
    );
}

struct MyApp {
    checked: Arc<Mutex<bool>>,
    money: Arc<Mutex<u32>>,
}

impl MyApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let ctx = &cc.egui_ctx;
        // Start with the default fonts (we will be adding to them rather than replacing them).
        let mut fonts = egui::FontDefinitions::default();

        // Install my own font (maybe supporting non-latin characters).
        // .ttf and .otf files supported.
        fonts.font_data.insert(
            "my_font".to_owned(),
            egui::FontData::from_static(include_bytes!("../SIMSUN.TTC")),
        );

        // Put my font first (highest priority) for proportional text:
        fonts
            .families
            .entry(egui::FontFamily::Proportional)
            .or_default()
            .insert(0, "my_font".to_owned());

        // Put my font as last fallback for monospace:
        fonts
            .families
            .entry(egui::FontFamily::Monospace)
            .or_default()
            .push("my_font".to_owned());

        // Tell egui to use these fonts:
        ctx.set_fonts(fonts);
        Self {
            checked: Arc::new(Mutex::new(false)),
            money: Arc::new(Mutex::new(9999)),
        }
    }
}

impl eframe::App for MyApp {
    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        let Self { checked, money } = self;
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.horizontal(|ui| {
                let checked_c1 = Arc::clone(&checked);
                let money_c1 = Arc::clone(&money);
                let checked1 = &mut *checked_c1.lock();
                let money1 = &mut *money_c1.lock();
                let checkbox = ui.checkbox(checked1, "修改金币");
                ui.add(
                    DragValue::new(money1)
                        .speed(100)
                        .min_decimals(0)
                        .max_decimals(999999),
                );
                if checkbox.changed() {
                    let checked_c2 = Arc::clone(&checked);
                    let money_c2 = Arc::clone(&money);

                    unsafe {
                        let handle = thread::spawn(move || {
                            let mut process_id = 0;
                            let window = FindWindowA(PCSTR(ptr::null()), s!("Brotato"));
                            GetWindowThreadProcessId(window, Some(&mut process_id));

                            let h_process =
                                OpenProcess(PROCESS_ALL_ACCESS, BOOL(0), process_id).unwrap();

                            let mut module_vec = [0u64, 1];
                            EnumProcessModules(
                                h_process,
                                module_vec.as_mut_ptr() as *mut HMODULE,
                                8,
                                &mut 0,
                            )
                            .unwrap();
                            let mut m_ptr = module_vec[0];
                            for i in OFFSET_VEC {
                                m_ptr = read_u64(m_ptr, i, h_process);
                            }
                            let ptr: *const u64 = (m_ptr + OFFSET_LAST) as *const u64;
                            let buffer = [0; 1];

                            loop {
                                {
                                    let checked = &mut *checked_c2.lock();
                                    let money = &mut *money_c2.lock();
                                    if !*checked {
                                        break;
                                    }
                                    ReadProcessMemory(
                                        h_process,
                                        ptr as *const c_void,
                                        buffer.as_ptr() as *mut c_void,
                                        8,
                                        None,
                                    )
                                    .unwrap();
                                    // info!("当前金钱：{:?}", buffer[0]);
                                    println!("当前金钱{:?}", buffer[0]);
                                    let write_buffer = [*money];
                                    WriteProcessMemory(
                                        h_process,
                                        ptr as *const c_void,
                                        write_buffer.as_ptr() as *mut c_void,
                                        8,
                                        None,
                                    )
                                    .unwrap();
                                }

                                sleep(Duration::from_secs(1));
                            }
                        });

                        if !*checked1 {
                            drop(handle)
                        };
                    }
                }
            });
        });
    }
}
