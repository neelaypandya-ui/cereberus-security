use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// OS-specific flags to hide the console window on Windows.
#[cfg(windows)]
use std::os::windows::process::CommandExt;
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;

/// Find the Python interpreter.
/// Priority: CEREBERUS_PYTHON env var → `python` on PATH.
pub fn find_python() -> Result<PathBuf, String> {
    // 1. Explicit env var
    if let Ok(p) = std::env::var("CEREBERUS_PYTHON") {
        let path = PathBuf::from(&p);
        if path.exists() {
            return Ok(path);
        }
        return Err(format!(
            "CEREBERUS_PYTHON is set to '{}' but the file does not exist",
            p
        ));
    }

    // 2. Probe PATH via `python --version`
    let probe = Command::new("python")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    match probe {
        Ok(status) if status.success() => Ok(PathBuf::from("python")),
        _ => Err(
            "Could not find Python. Install Python 3.11+ or set CEREBERUS_PYTHON env var."
                .to_string(),
        ),
    }
}

/// Resolve the Cereberus project root directory.
/// Priority: CEREBERUS_ROOT env var → CWD (if backend/ exists) → relative to exe.
pub fn resolve_project_root() -> Result<PathBuf, String> {
    // 1. Explicit env var
    if let Ok(root) = std::env::var("CEREBERUS_ROOT") {
        let path = PathBuf::from(&root);
        if path.join("backend").is_dir() {
            return Ok(path);
        }
        return Err(format!(
            "CEREBERUS_ROOT='{}' does not contain a backend/ directory",
            root
        ));
    }

    // 2. Current working directory
    if let Ok(cwd) = std::env::current_dir() {
        if cwd.join("backend").is_dir() {
            return Ok(cwd);
        }
        // Maybe CWD is the repo root and project is in cereberus/
        let sub = cwd.join("cereberus");
        if sub.join("backend").is_dir() {
            return Ok(sub);
        }
    }

    // 3. Relative to the executable (exe is in src-tauri/target/... or installed)
    if let Ok(exe) = std::env::current_exe() {
        // Walk up from exe looking for backend/
        let mut dir = exe.parent().map(|p| p.to_path_buf());
        for _ in 0..6 {
            if let Some(ref d) = dir {
                if d.join("backend").is_dir() {
                    return Ok(d.clone());
                }
                dir = d.parent().map(|p| p.to_path_buf());
            } else {
                break;
            }
        }
    }

    Err("Cannot find Cereberus project root. Set CEREBERUS_ROOT env var.".to_string())
}

/// Check if port 8000 already has a healthy Cereberus backend running.
pub fn check_existing_backend() -> bool {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .ok();

    if let Some(client) = client {
        if let Ok(resp) = client.get("http://127.0.0.1:8000/api/v1/auth/login").send() {
            // Any response (even 405 Method Not Allowed) means the server is up
            return resp.status().as_u16() > 0;
        }
    }
    false
}

/// Spawn the uvicorn backend as a child process.
/// Returns the Child handle (caller owns the process lifetime).
pub fn spawn_backend(python: &PathBuf, project_root: &PathBuf) -> Result<Child, String> {
    let mut cmd = Command::new(python.as_os_str());
    cmd.args([
        "-m",
        "uvicorn",
        "backend.main:app",
        "--host",
        "127.0.0.1",
        "--port",
        "8000",
    ])
    .current_dir(project_root)
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());

    // Hide the console window on Windows
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);

    cmd.spawn()
        .map_err(|e| format!("Failed to spawn backend: {}", e))
}

/// Poll the backend health endpoint until it responds, or timeout.
pub fn wait_for_backend(timeout: Duration) -> Result<(), String> {
    let start = Instant::now();
    let poll_interval = Duration::from_millis(500);

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

    loop {
        if start.elapsed() > timeout {
            return Err(format!(
                "Backend did not become healthy within {} seconds",
                timeout.as_secs()
            ));
        }

        if let Ok(resp) = client.get("http://127.0.0.1:8000/api/v1/auth/login").send() {
            if resp.status().as_u16() > 0 {
                return Ok(());
            }
        }

        std::thread::sleep(poll_interval);
    }
}

/// Kill the backend process tree on Windows using taskkill.
pub fn shutdown_backend(child: &mut Child) {
    let pid = child.id();

    #[cfg(windows)]
    {
        let mut kill_cmd = Command::new("taskkill");
        kill_cmd.args(["/PID", &pid.to_string(), "/T", "/F"]);
        kill_cmd.creation_flags(CREATE_NO_WINDOW);
        let _ = kill_cmd.status();
    }

    #[cfg(not(windows))]
    {
        let _ = child.kill();
    }

    let _ = child.wait();
}

/// Drain stdout/stderr of the child process in background threads
/// so the pipes don't fill up and block the process.
pub fn drain_child_output(child: &mut Child) {
    if let Some(stdout) = child.stdout.take() {
        std::thread::spawn(move || {
            let reader = BufReader::new(stdout);
            for line in reader.lines() {
                if line.is_err() {
                    break;
                }
            }
        });
    }
    if let Some(stderr) = child.stderr.take() {
        std::thread::spawn(move || {
            let reader = BufReader::new(stderr);
            for line in reader.lines() {
                if line.is_err() {
                    break;
                }
            }
        });
    }
}
