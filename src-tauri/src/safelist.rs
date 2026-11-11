//! The safe-list: a last line of defence that every scan and every delete goes through.
//! Built-in rules protect the OS, installed programs and personal files; users can add
//! their own patterns in settings.

use std::path::Path;

use serde::Serialize;

/// Folders that are never touched, even if a cleanup target resolves inside them.
/// Matched as case-insensitive path prefixes after environment expansion.
const PROTECTED_ROOTS: &[&str] = &[
    r"%WINDIR%\System32",
    r"%WINDIR%\SysWOW64",
    r"%WINDIR%\WinSxS",
    r"%WINDIR%\Fonts",
    r"%PROGRAMFILES%",
    r"%PROGRAMFILES(X86)%",
    r"%USERPROFILE%\Documents",
    r"%USERPROFILE%\Desktop",
    r"%USERPROFILE%\Pictures",
    r"%USERPROFILE%\Videos",
    r"%USERPROFILE%\Music",
    r"%USERPROFILE%\OneDrive",
    r"%USERPROFILE%\.ssh",
    r"%APPDATA%\Microsoft\Credentials",
    r"%LOCALAPPDATA%\Microsoft\Credentials",
];

/// File names and extensions that hold irreplaceable data. Matched anywhere.
const PROTECTED_PATTERNS: &[&str] = &[
    "*.kdbx", "*.pst", "*.ost", "*.wallet", "wallet.dat", "*.pfx", "*.p12", "*.key",
    "*.vhdx", "*.vmdk", "*.psd", "*.blend", "*.docx", "*.xlsx", "*.pptx", "*.sqlite-wal",
    "ntuser.dat*", "pagefile.sys", "hiberfil.sys", "swapfile.sys",
];

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SafeRule {
    pub pattern: String,
    pub built_in: bool,
    pub reason: &'static str,
}

#[derive(Debug, Clone)]
pub struct SafeList {
    roots: Vec<String>,
    patterns: Vec<String>,
    user: Vec<String>,
}

impl SafeList {
    pub fn new(user_patterns: &[String]) -> Self {
        Self {
            roots: PROTECTED_ROOTS.iter().filter_map(|r| expand_env(r)).map(|r| normalize(&r)).collect(),
            patterns: PROTECTED_PATTERNS.iter().map(|p| p.to_lowercase()).collect(),
            user: user_patterns.iter().filter_map(|p| expand_env(p)).map(|p| normalize(&p)).collect(),
        }
    }

    /// Builds a list from explicit values (no environment lookups); used by tests.
    #[cfg(test)]
    pub fn with_roots(roots: &[&str], user: &[&str]) -> Self {
        Self {
            roots: roots.iter().map(|r| normalize(r)).collect(),
            patterns: PROTECTED_PATTERNS.iter().map(|p| p.to_lowercase()).collect(),
            user: user.iter().map(|u| normalize(u)).collect(),
        }
    }

    /// Returns the reason a path is protected, or `None` when it may be cleaned.
    pub fn protects(&self, path: &Path) -> Option<&'static str> {
        let full = normalize(&path.to_string_lossy());
        if self.roots.iter().any(|r| is_within(&full, r)) {
            return Some("system or personal folder");
        }
        let name = path.file_name().map(|n| n.to_string_lossy().to_lowercase()).unwrap_or_default();
        if self.patterns.iter().any(|p| wildcard_match(p, &name)) {
            return Some("personal or system file type");
        }
        if self.user.iter().any(|u| wildcard_match(u, &full) || is_within(&full, u)) {
            return Some("on your safe-list");
        }
        None
    }

    pub fn rules(&self) -> Vec<SafeRule> {
        let mut out: Vec<SafeRule> = self
            .roots
            .iter()
            .map(|r| SafeRule { pattern: r.clone(), built_in: true, reason: "system or personal folder" })
            .collect();
        out.extend(self.patterns.iter().map(|p| SafeRule { pattern: p.clone(), built_in: true, reason: "personal or system file type" }));
        out.extend(self.user.iter().map(|u| SafeRule { pattern: u.clone(), built_in: false, reason: "on your safe-list" }));
        out
    }
}

fn normalize(p: &str) -> String {
    let mut s = p.replace('/', "\\").to_lowercase();
    while s.ends_with('\\') && s.len() > 3 {
        s.pop();
    }
    s
}

fn is_within(path: &str, root: &str) -> bool {
    path == root || (path.starts_with(root) && path.as_bytes().get(root.len()) == Some(&b'\\'))
}

/// Expands `%VAR%` tokens. Returns `None` if a variable is not set, so a missing
/// variable can never turn a rule into something broader like `\System32`.
pub fn expand_env(input: &str) -> Option<String> {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        let end = after.find('%')?;
        let value = std::env::var(&after[..end]).ok()?;
        out.push_str(&value);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Some(out)
}

/// Minimal `*` / `?` wildcard matcher (iterative, no allocation).
pub fn wildcard_match(pattern: &str, text: &str) -> bool {
    let (p, t) = (pattern.as_bytes(), text.as_bytes());
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark) = (None::<usize>, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == b'?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn list() -> SafeList {
        SafeList::with_roots(&[r"C:\Windows\System32", r"C:\Users\alex\Documents"], &[r"d:\projects\*"])
    }

    #[test]
    fn protects_system_folders_case_insensitively() {
        let l = list();
        assert!(l.protects(&PathBuf::from(r"C:\WINDOWS\system32\drivers\etc\hosts")).is_some());
        assert!(l.protects(&PathBuf::from(r"C:\Windows\System32")).is_some());
        assert!(l.protects(&PathBuf::from(r"C:\Windows\System32Backup\x.tmp")).is_none());
    }

    #[test]
    fn protects_personal_file_types_anywhere() {
        let l = list();
        assert!(l.protects(&PathBuf::from(r"C:\Users\alex\AppData\Local\Temp\vault.kdbx")).is_some());
        assert!(l.protects(&PathBuf::from(r"C:\Temp\Report Q3.DOCX")).is_some());
        assert!(l.protects(&PathBuf::from(r"C:\Temp\setup-4821.tmp")).is_none());
    }

    #[test]
    fn user_patterns_apply() {
        let l = list();
        assert_eq!(l.protects(&PathBuf::from(r"D:\Projects\site\cache\a.bin")), Some("on your safe-list"));
    }

    #[test]
    fn wildcard_matching() {
        assert!(wildcard_match("*.tmp", "a.tmp"));
        assert!(wildcard_match("ntuser.dat*", "ntuser.dat.log1"));
        assert!(wildcard_match("f?le", "file"));
        assert!(!wildcard_match("*.tmp", "a.tmpx"));
        assert!(wildcard_match("*", ""));
    }

    #[test]
    fn missing_env_var_disables_rule() {
        assert_eq!(expand_env("%TIDY_SURELY_UNSET_VAR%\\System32"), None);
        assert_eq!(expand_env(r"C:\plain").as_deref(), Some(r"C:\plain"));
    }
}
