//! Tauri commands: the only surface the UI talks to.

use std::path::PathBuf;

use serde::Serialize;
use tauri::State;

use crate::files::{self, FilesReport};
use crate::health::{self, Drive, MemoryInfo};
use crate::processes::{self, ProcessRow, SortBy};
use crate::safelist::{SafeList, SafeRule};
use crate::scanner::{self, CleanReport, ScanReport};
use crate::startup::{self, StartupItem};
use crate::state::{AppState, Settings, TidyError, TidyResult};

fn demo_mode() -> bool {
    std::env::var_os("TIDY_DEMO").is_some()
}

fn safe_list(settings: &Settings) -> SafeList {
    SafeList::new(&settings.safe_list)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Overview {
    pub host: String,
    pub os: String,
    pub uptime_secs: u64,
    pub cpu_percent: f32,
    pub memory: MemoryInfo,
    pub drives: Vec<Drive>,
    pub top: Vec<ProcessRow>,
    pub reclaimable: u64,
    pub last_scan_ms: Option<u64>,
    pub dry_run: bool,
}

#[tauri::command]
pub fn get_overview(state: State<'_, AppState>) -> TidyResult<Overview> {
    let (reclaimable, last_scan_ms) = state
        .last_scan
        .lock()
        .ok()
        .and_then(|s| s.as_ref().map(|r| (selected_bytes(r), Some(r.duration_ms))))
        .unwrap_or((0, None));
    let sys = state.sys.lock().map_err(|_| TidyError::Other("system lock poisoned".into()))?;
    let mut top = processes::snapshot(&sys, SortBy::Cpu, 5);
    drop_history(&state, &mut top);
    Ok(Overview {
        host: sysinfo::System::host_name().unwrap_or_else(|| "This PC".into()),
        os: sysinfo::System::long_os_version().unwrap_or_else(|| "Windows".into()),
        uptime_secs: sysinfo::System::uptime(),
        cpu_percent: sys.global_cpu_usage(),
        memory: health::memory(&sys),
        drives: health::drives(reclaimable),
        top,
        reclaimable,
        last_scan_ms,
        dry_run: state.settings().dry_run,
    })
}

fn drop_history(state: &AppState, rows: &mut [ProcessRow]) {
    for r in rows {
        r.history = state.history_of(&r.name);
    }
}

fn selected_bytes(r: &ScanReport) -> u64 {
    r.categories.iter().filter(|c| c.selected).map(|c| c.bytes).sum()
}

/// Smart Scan. Runs on a worker thread so the window keeps painting.
#[tauri::command]
pub async fn smart_scan(state: State<'_, AppState>) -> TidyResult<ScanReport> {
    let settings = state.settings();
    let report = if demo_mode() {
        scanner::sample_report()
    } else {
        tauri::async_runtime::spawn_blocking(move || {
            let targets = scanner::default_targets(settings.min_temp_age_hours);
            scanner::scan(&targets, &safe_list(&settings), &settings.unchecked_categories)
        })
        .await
        .map_err(|e| TidyError::Other(e.to_string()))?
    };
    log::info!("smart scan: {} in {} ms", crate::state::human_bytes(report.total_bytes), report.duration_ms);
    if let Ok(mut last) = state.last_scan.lock() {
        *last = Some(report.clone());
    }
    Ok(report)
}

/// Cleans the given categories. `dry_run` defaults to the setting (on by default);
/// a real delete needs both `dry_run: false` here and dry-run disabled in settings.
#[tauri::command]
pub async fn clean(state: State<'_, AppState>, categories: Vec<String>, dry_run: Option<bool>) -> TidyResult<CleanReport> {
    if state.last_scan.lock().map(|s| s.is_none()).unwrap_or(true) {
        return Err(TidyError::NoScan);
    }
    let settings = state.settings();
    let dry = settings.dry_run || dry_run.unwrap_or(true) || demo_mode();
    let report = tauri::async_runtime::spawn_blocking(move || {
        let targets = scanner::default_targets(settings.min_temp_age_hours);
        scanner::clean(&targets, &categories, &safe_list(&settings), dry)
    })
    .await
    .map_err(|e| TidyError::Other(e.to_string()))?;
    if !report.dry_run {
        if let Ok(mut last) = state.last_scan.lock() {
            *last = None;
        }
    }
    Ok(report)
}

#[tauri::command]
pub fn list_processes(state: State<'_, AppState>, sort: Option<SortBy>, limit: Option<usize>) -> TidyResult<Vec<ProcessRow>> {
    let sys = state.sys.lock().map_err(|_| TidyError::Other("system lock poisoned".into()))?;
    let mut rows = processes::snapshot(&sys, sort.unwrap_or_default(), limit.unwrap_or(60));
    drop(sys);
    drop_history(&state, &mut rows);
    Ok(rows)
}

#[tauri::command]
pub fn end_process(state: State<'_, AppState>, name: String) -> TidyResult<u32> {
    let sys = state.sys.lock().map_err(|_| TidyError::Other("system lock poisoned".into()))?;
    processes::end_process(&sys, &name).map_err(TidyError::Other)
}

#[tauri::command]
pub fn get_memory(state: State<'_, AppState>) -> TidyResult<MemoryInfo> {
    let sys = state.sys.lock().map_err(|_| TidyError::Other("system lock poisoned".into()))?;
    Ok(health::memory(&sys))
}

#[tauri::command]
pub fn purge_standby() -> TidyResult<()> {
    health::purge_standby().map_err(TidyError::NotImplemented)
}

#[tauri::command]
pub fn list_drives(state: State<'_, AppState>) -> Vec<Drive> {
    let junk = state.last_scan.lock().ok().and_then(|s| s.as_ref().map(selected_bytes)).unwrap_or(0);
    health::drives(junk)
}

#[tauri::command]
pub fn list_startup() -> Vec<StartupItem> {
    startup::list()
}

/// The per-user Startup folder, shown as a hint under the startup list.
#[tauri::command]
pub fn get_startup_folder() -> Option<String> {
    startup::startup_folder()
}

#[tauri::command]
pub fn set_startup_enabled(id: String, enabled: bool) -> TidyResult<()> {
    startup::set_enabled(&id, enabled).map_err(TidyError::Other)
}

/// Large & duplicate files under `root` (defaults to the user profile).
#[tauri::command]
pub async fn find_large_files(state: State<'_, AppState>, root: Option<String>, min_mb: Option<u64>) -> TidyResult<FilesReport> {
    let settings = state.settings();
    let root = root
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("USERPROFILE").map(PathBuf::from))
        .ok_or_else(|| TidyError::Other("no folder to scan".into()))?;
    if !root.is_dir() {
        return Err(TidyError::Other(format!("{} is not a folder", root.display())));
    }
    let safe = safe_list(&settings);
    if safe.protects(&root).is_some() {
        return Err(TidyError::Protected(root.display().to_string()));
    }
    let min = min_mb.unwrap_or(settings.large_file_min_mb) * 1024 * 1024;
    tauri::async_runtime::spawn_blocking(move || files::scan(&root, min, &safe, 50))
        .await
        .map_err(|e| TidyError::Other(e.to_string()))
}

#[tauri::command]
pub fn get_settings(state: State<'_, AppState>) -> Settings {
    state.settings()
}

#[tauri::command]
pub fn save_settings(state: State<'_, AppState>, settings: Settings) -> TidyResult<Settings> {
    let clean = Settings::parse(&serde_json::to_string(&settings)?)?;
    clean.save()?;
    if let Ok(mut s) = state.settings.lock() {
        *s = clean.clone();
    }
    Ok(clean)
}

#[tauri::command]
pub fn get_safe_list(state: State<'_, AppState>) -> Vec<SafeRule> {
    safe_list(&state.settings()).rules()
}

/// Lets the UI explain why a path in a result list is greyed out.
#[tauri::command]
pub fn check_path(state: State<'_, AppState>, path: String) -> Option<&'static str> {
    safe_list(&state.settings()).protects(&PathBuf::from(path))
}
