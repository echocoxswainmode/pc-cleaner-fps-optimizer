//! Startup apps from the registry Run keys, with an estimated boot impact.

use std::path::Path;

use serde::Serialize;
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ};
use winreg::RegKey;

const RUN: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const RUN_WOW: &str = r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run";
const APPROVED: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";
const APPROVED_32: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32";

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Impact {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StartupItem {
    pub id: String,
    pub name: String,
    pub command: String,
    pub exe: String,
    pub args: String,
    pub source: &'static str,
    pub enabled: bool,
    pub impact: Impact,
    pub exe_bytes: u64,
    pub exists: bool,
}

/// Apps known to do heavy work at sign-in (updaters, sync clients, launchers).
const HEAVY: &[&str] = &[
    "teams", "onedrive", "steam", "epicgameslauncher", "battle.net", "origin", "eadesktop", "creative cloud",
    "adobe", "dropbox", "googledrivefs", "icloud", "spotify", "nvidia", "razer", "corsair", "logioptionsplus",
];
const LIGHT: &[&str] = &["securityhealth", "rtkaud", "realtek", "igfx", "ctfmon", "bthelper", "synaptics"];

/// Splits a Run value into executable and arguments. Handles quoted paths,
/// unquoted paths with spaces that end in `.exe`, and `rundll32` style commands.
pub fn split_command(cmd: &str) -> (String, String) {
    let cmd = cmd.trim();
    if let Some(rest) = cmd.strip_prefix('"') {
        if let Some(end) = rest.find('"') {
            return (rest[..end].to_string(), rest[end + 1..].trim().to_string());
        }
        return (rest.to_string(), String::new());
    }
    let lower = cmd.to_lowercase();
    if let Some(pos) = lower.find(".exe") {
        let end = pos + 4;
        if end == cmd.len() || cmd.as_bytes()[end] == b' ' {
            return (cmd[..end].to_string(), cmd[end..].trim().to_string());
        }
    }
    match cmd.split_once(' ') {
        Some((exe, args)) => (exe.to_string(), args.trim().to_string()),
        None => (cmd.to_string(), String::new()),
    }
}

/// Rates boot impact from what the app is and how big its binary is.
pub fn rate(name: &str, exe: &str, exe_bytes: u64) -> Impact {
    let hay = format!("{} {}", name, exe).to_lowercase();
    if HEAVY.iter().any(|h| hay.contains(h)) {
        return Impact::High;
    }
    if LIGHT.iter().any(|l| hay.contains(l)) {
        return Impact::Low;
    }
    match exe_bytes {
        0 => Impact::Low,
        b if b > 40 * 1024 * 1024 => Impact::High,
        b if b > 6 * 1024 * 1024 => Impact::Medium,
        _ => Impact::Low,
    }
}

/// Windows stores the Task Manager "Disabled" toggle in StartupApproved:
/// first byte 0x02/0x06 = enabled, 0x03/0x07 = disabled.
pub fn approved_flag(bytes: &[u8]) -> bool {
    bytes.first().is_none_or(|b| b & 1 == 0)
}

fn is_enabled(root: &RegKey, approved: &str, name: &str) -> bool {
    root.open_subkey_with_flags(approved, KEY_READ)
        .and_then(|k| k.get_raw_value(name))
        .map(|v| approved_flag(&v.bytes))
        .unwrap_or(true)
}

fn read_key(hive: &RegKey, path: &str, approved: &str, source: &'static str, out: &mut Vec<StartupItem>) {
    let Ok(key) = hive.open_subkey_with_flags(path, KEY_READ) else { return };
    for (name, value) in key.enum_values().flatten() {
        let command = value.to_string();
        if command.trim().is_empty() {
            continue;
        }
        let (exe, args) = split_command(&expand(&command));
        let meta = std::fs::metadata(&exe).ok();
        let exe_bytes = meta.as_ref().map(|m| m.len()).unwrap_or(0);
        out.push(StartupItem {
            id: format!("{source}|{name}"),
            impact: rate(&name, &exe, exe_bytes),
            enabled: is_enabled(hive, approved, &name),
            exists: meta.is_some(),
            name,
            command,
            exe,
            args,
            source,
            exe_bytes,
        });
    }
}

fn expand(s: &str) -> String {
    crate::safelist::expand_env(s).unwrap_or_else(|| s.to_string())
}

/// Reads HKCU and HKLM Run keys (both 64- and 32-bit views).
pub fn list() -> Vec<StartupItem> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let mut items = Vec::new();
    read_key(&hkcu, RUN, APPROVED, "HKCU Run", &mut items);
    read_key(&hklm, RUN, APPROVED, "HKLM Run", &mut items);
    read_key(&hklm, RUN_WOW, APPROVED_32, "HKLM Run (32-bit)", &mut items);
    items.sort_by(|a, b| b.impact.cmp(&a.impact).then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase())));
    items
}

/// Enables or disables a startup entry the same way Task Manager does.
pub fn set_enabled(id: &str, enabled: bool) -> Result<(), String> {
    let (source, name) = id.split_once('|').ok_or("bad startup id")?;
    // TODO(owner): write a 12-byte REG_BINARY to StartupApproved\Run(32) in the
    // matching hive: [0x02 or 0x03, 0, 0, 0] + FILETIME of the change. HKLM needs admin.
    log::info!("startup toggle requested: {source} / {name} -> {enabled}");
    Err("changing startup apps arrives in 1.1; use Task Manager > Startup for now".into())
}

/// Path to the per-user Startup folder (shortcuts there also run at sign-in).
pub fn startup_folder() -> Option<String> {
    let p = expand(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup");
    Path::new(&p).is_dir().then_some(p)
    // TODO(owner): resolve .lnk targets in this folder and merge them into list().
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_quoted_commands() {
        let (exe, args) = split_command(r#""C:\Program Files\Steam\steam.exe" -silent"#);
        assert_eq!(exe, r"C:\Program Files\Steam\steam.exe");
        assert_eq!(args, "-silent");
    }

    #[test]
    fn splits_unquoted_paths_with_spaces() {
        let (exe, args) = split_command(r"C:\Program Files\Realtek\Audio\RtkAudUService64.exe -background");
        assert_eq!(exe, r"C:\Program Files\Realtek\Audio\RtkAudUService64.exe");
        assert_eq!(args, "-background");
        assert_eq!(split_command("ctfmon.exe").0, "ctfmon.exe");
        assert_eq!(split_command("rundll32 shell32.dll,Control_RunDLL").1, "shell32.dll,Control_RunDLL");
    }

    #[test]
    fn ratings() {
        assert_eq!(rate("Steam", r"C:\Steam\steam.exe", 4_000_000), Impact::High);
        assert_eq!(rate("SecurityHealth", "SecurityHealthSystray.exe", 90_000_000), Impact::Low);
        assert_eq!(rate("Tool", "tool.exe", 12 * 1024 * 1024), Impact::Medium);
        assert_eq!(rate("Missing", "gone.exe", 0), Impact::Low);
    }

    #[test]
    fn approved_flags() {
        assert!(approved_flag(&[0x02, 0, 0, 0]));
        assert!(approved_flag(&[0x06]));
        assert!(!approved_flag(&[0x03, 0, 0, 0]));
        assert!(approved_flag(&[]));
    }
}
