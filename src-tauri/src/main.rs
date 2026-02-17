// Prevents an extra console window on Windows in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod sidecar;

use std::process::Child;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tauri::Manager;

/// Shared state: the backend child process (if we spawned one).
#[allow(dead_code)]
struct BackendProcess(Arc<Mutex<Option<Child>>>);

/// HTML loading screen shown while the backend is starting up.
const LOADING_HTML: &str = "data:text/html,\
<!DOCTYPE html>\
<html><head><style>\
*{margin:0;padding:0;box-sizing:border-box;}\
body{background:%230a0a0f;color:%2300ff88;font-family:'Segoe UI',Consolas,monospace;\
display:flex;align-items:center;justify-content:center;height:100vh;flex-direction:column;}\
h1{font-size:2.5rem;letter-spacing:0.3em;margin-bottom:1rem;}\
.spinner{width:48px;height:48px;border:4px solid %23113322;\
border-top:4px solid %2300ff88;border-radius:50%25;\
animation:spin 1s linear infinite;margin-bottom:1.5rem;}\
@keyframes spin{to{transform:rotate(360deg);}}\
p{color:%23557766;font-size:0.9rem;}\
</style></head><body>\
<h1>CEREBERUS</h1>\
<div class='spinner'></div>\
<p>Initializing defense systems...</p>\
</body></html>";

fn main() {
    let backend_handle = Arc::new(Mutex::new(None::<Child>));
    let backend_for_setup = backend_handle.clone();
    let backend_for_exit = backend_handle.clone();

    tauri::Builder::default()
        .manage(BackendProcess(backend_handle))
        .setup(move |app| {
            let window = app.get_webview_window("main").expect("no main window");

            // Show loading screen immediately
            if let Ok(url) = LOADING_HTML.parse() {
                let _ = window.navigate(url);
            }

            let window_clone = window.clone();
            let state = backend_for_setup.clone();

            // Spawn backend and poll health in a background thread
            // so the window renders the loading screen immediately.
            std::thread::spawn(move || {
                // 1. Check if a backend is already running (e.g. Windows Service)
                let already_running = sidecar::check_existing_backend();

                if !already_running {
                    // 2. Find python and project root
                    let python = match sidecar::find_python() {
                        Ok(p) => p,
                        Err(e) => {
                            eprintln!("CEREBERUS ERROR: {}", e);
                            show_error(&window_clone, &e);
                            return;
                        }
                    };

                    let root = match sidecar::resolve_project_root() {
                        Ok(r) => r,
                        Err(e) => {
                            eprintln!("CEREBERUS ERROR: {}", e);
                            show_error(&window_clone, &e);
                            return;
                        }
                    };

                    println!("CEREBERUS: Python = {:?}", python);
                    println!("CEREBERUS: Root   = {:?}", root);

                    // 3. Spawn the backend
                    match sidecar::spawn_backend(&python, &root) {
                        Ok(mut child) => {
                            println!("CEREBERUS: Backend spawned (PID {})", child.id());
                            sidecar::drain_child_output(&mut child);
                            let mut guard = state.lock().unwrap();
                            *guard = Some(child);
                        }
                        Err(e) => {
                            eprintln!("CEREBERUS ERROR: {}", e);
                            show_error(&window_clone, &e);
                            return;
                        }
                    }
                } else {
                    println!("CEREBERUS: Existing backend detected on port 8000, reusing.");
                }

                // 4. Wait for the backend to become healthy
                match sidecar::wait_for_backend(Duration::from_secs(60)) {
                    Ok(()) => {
                        println!("CEREBERUS: Backend is healthy — loading UI.");
                        if let Ok(url) = "http://127.0.0.1:8000".parse() {
                            let _ = window_clone.navigate(url);
                        }
                    }
                    Err(e) => {
                        eprintln!("CEREBERUS ERROR: {}", e);
                        show_error(&window_clone, &e);
                    }
                }
            });

            Ok(())
        })
        .on_window_event(move |_window, event| {
            if let tauri::WindowEvent::Destroyed = event {
                let mut guard = backend_for_exit.lock().unwrap();
                if let Some(ref mut child) = *guard {
                    println!("CEREBERUS: Shutting down backend (PID {})...", child.id());
                    sidecar::shutdown_backend(child);
                    println!("CEREBERUS: Backend terminated.");
                }
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running CEREBERUS");
}

/// Navigate the window to an error page.
fn show_error(window: &tauri::WebviewWindow, message: &str) {
    let encoded = message
        .replace('%', "%25")
        .replace(' ', "%20")
        .replace('\'', "%27")
        .replace('"', "%22");
    let html = format!(
        "data:text/html,\
<!DOCTYPE html>\
<html><head><style>\
body{{background:%230a0a0f;color:%23ff4444;font-family:Consolas,monospace;\
display:flex;align-items:center;justify-content:center;height:100vh;\
flex-direction:column;text-align:center;padding:2rem;}}\
h1{{margin-bottom:1rem;color:%23ff6666;}}\
p{{color:%23aa4444;max-width:600px;line-height:1.6;}}\
</style></head><body>\
<h1>CEREBERUS — Startup Error</h1>\
<p>{}</p>\
</body></html>",
        encoded
    );
    if let Ok(url) = html.parse() {
        let _ = window.navigate(url);
    }
}
