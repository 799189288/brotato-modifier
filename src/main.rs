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
            ProcessStatus::EnumProcessModules,
            Threading::{OpenProcess, PROCESS_ALL_ACCESS},
        },
        UI::WindowsAndMessaging::{FindWindowA, GetWindowThreadProcessId},
    },
};
const MONEY_LAST: u64 = 0x200;
const MONEY_OFFSET: [u64; 6] = [0x025362D0, 0x148, 0x108, 0x38, 0x58, 0x20];

const LUCKY_LAST: u64 = 0x210;
const LUCKY_OFFSET: [u64; 5] = [0x0253A1F0, 0xA8, 0x2C0, 0x10, 0xA8];

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

        base_ptr_deref[0]
    }
}

fn lock_value<T: Sync + Send + 'static + Copy + Debug + Default>(
    val: Arc<Mutex<T>>,
    ischecked: Arc<Mutex<bool>>,
    flag: String,
    last_offset: u64,
    offsets: Vec<u64>,
) {
    unsafe {
        let handle = thread::spawn(move || {
            let mut process_id = 0;
            let window = FindWindowA(PCSTR(ptr::null()), s!("Brotato"));
            GetWindowThreadProcessId(window, Some(&mut process_id));

            let h_process = OpenProcess(PROCESS_ALL_ACCESS, BOOL(0), process_id).unwrap();

            let mut module_vec = [0u64, 1];
            EnumProcessModules(
                h_process,
                module_vec.as_mut_ptr() as *mut HMODULE,
                8,
                &mut 0,
            )
            .unwrap();
            let mut m_ptr = module_vec[0];
            for i in offsets {
                m_ptr = read_u64(m_ptr, i, h_process);
            }
            let ptr: *const u64 = (m_ptr + last_offset) as *const u64;
            println!("{:?}", val.lock());
            loop {
                {
                    let checked = &mut *ischecked.lock();
                    let current_value = &mut *val.lock();
                    if !*checked {
                        break;
                    }
                    let buffer = [T::default(); 1];
                    ReadProcessMemory(
                        h_process,
                        ptr as *const c_void,
                        buffer.as_ptr() as *mut c_void,
                        8,
                        None,
                    )
                    .unwrap();
                    // info!("当前金钱：{:?}", buffer[0]);
                    println!("当前{:?}{:?}", flag, buffer[0]);
                    let write_buffer = [*current_value];
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
        Box::new(|cc| Ok(Box::new(MyApp::new(cc)))),
    );
}

struct MyApp {
    m_checked: Arc<Mutex<bool>>,
    c_checked: Arc<Mutex<bool>>,
    money: Arc<Mutex<u64>>,
    lucky: Arc<Mutex<u64>>,
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
            m_checked: Arc::new(Mutex::new(false)),
            c_checked: Arc::new(Mutex::new(false)),
            money: Arc::new(Mutex::new(9999)),
            lucky: Arc::new(Mutex::new(999)),
        }
    }
}

impl eframe::App for MyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let Self {
            m_checked,
            c_checked,
            money,
            lucky,
        } = self;
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.horizontal(|ui| {
                let checked_c1 = Arc::clone(&m_checked);
                let money_c1 = Arc::clone(&money);
                let checked1 = &mut *checked_c1.lock();
                let money1 = &mut *money_c1.lock();
                let checkbox = ui.checkbox(checked1, "金币");
                ui.add(
                    DragValue::new(money1)
                        .speed(100)
                        .min_decimals(0)
                        .max_decimals(99),
                );
                if checkbox.changed() {
                    let checked_c2 = Arc::clone(&m_checked);
                    let money_c2 = Arc::clone(&money);
                    lock_value(
                        money_c2,
                        checked_c2,
                        "金钱".to_string(),
                        MONEY_LAST,
                        MONEY_OFFSET.to_vec(),
                    );
                }
            });
            ui.horizontal(|ui| {
                let checked_c1 = Arc::clone(&c_checked);
                let lucky_c1 = Arc::clone(&lucky);
                let checked1 = &mut *checked_c1.lock();
                let lucky1 = &mut *lucky_c1.lock();
                let checkbox = ui.checkbox(checked1, "幸运".to_string());
                ui.add(
                    DragValue::new(lucky1)
                        .speed(100)
                        .min_decimals(0)
                        .max_decimals(99),
                );
                if checkbox.changed() {
                    let checked_c2 = Arc::clone(&c_checked);
                    let lucky_c2 = Arc::clone(&lucky);
                    lock_value(
                        lucky_c2,
                        checked_c2,
                        "幸运".to_string(),
                        LUCKY_LAST,
                        LUCKY_OFFSET.to_vec(),
                    );
                }
            });
        });
    }
}
