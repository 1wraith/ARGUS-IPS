//! The configuration file, and the single option table behind it.
//!
//! A full-capability invocation was fourteen flags long, which is the
//! point at which an operator stops typing it and starts keeping it in a
//! text file somewhere — usually a shell script nobody version-controls.
//! Making that file a first-class input costs little and removes a whole
//! class of "it worked on the other host" incidents.
//!
//! # One name per setting, one table that knows them
//!
//! The obvious way to add a config file is a second parser that
//! translates file keys into the same internal fields the flag parser
//! sets. That is two lists of every option, and they drift: a flag added
//! to one is missing from the other, and the omission shows up as a
//! setting that silently does nothing.
//!
//! So there is exactly one table, in `main.rs`'s `apply`, and both
//! front-ends drive it. A config key *is* the flag name without its
//! leading dash — `rate-threshold = 500` is `-rate-threshold 500` — so
//! there is also only one name per setting to learn and document, and
//! `-help` documents the file too.
//!
//! This module's job is therefore only to turn a file into an ordered
//! list of `(key, value)` pairs, and to report where a bad one came
//! from.
//!
//! # Precedence
//!
//! Defaults, then the file, then the command line. A flag always wins,
//! which is what makes a config file safe to keep in production: an
//! operator can always override one setting for one run without editing
//! the deployed file.

use std::path::Path;

/// One setting, with the line it came from so errors can point at it.
pub struct Entry {
    pub key: String,
    pub value: String,
    pub line: usize,
}

pub struct ConfigFile {
    pub path: String,
    pub entries: Vec<Entry>,
}

/// Whether a value means yes. Accepts the spellings people actually
/// write, and refuses anything else rather than guessing — a silently
/// false `enabled = yess` is worse than a startup failure.
pub fn parse_bool(s: &str) -> anyhow::Result<bool> {
    match s.trim().to_ascii_lowercase().as_str() {
        "true" | "yes" | "on" | "1" => Ok(true),
        "false" | "no" | "off" | "0" => Ok(false),
        other => anyhow::bail!("{:?} is not a boolean (true/false, yes/no, on/off, 1/0)", other),
    }
}

impl ConfigFile {
    /// Parses `key = value` lines.
    ///
    /// `#` and `;` start a comment. `[section]` headers are accepted and
    /// ignored: they let a file be grouped for a reader without
    /// introducing a second namespace for the parser to disagree with.
    /// Values may be quoted, which is the only way to write a BPF filter
    /// containing a `#`.
    pub fn parse(path: &str, text: &str) -> anyhow::Result<ConfigFile> {
        let mut entries = Vec::new();
        for (i, raw) in text.lines().enumerate() {
            let line_no = i + 1;
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') || (line.starts_with('[') && line.ends_with(']')) {
                continue;
            }
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!("{}:{}: {:?} is not 'key = value'", path, line_no, line))?;
            let key = key.trim().trim_start_matches('-').to_string();
            anyhow::ensure!(!key.is_empty(), "{}:{}: empty key", path, line_no);
            entries.push(Entry { key, value: unquote(value.trim()), line: line_no });
        }
        Ok(ConfigFile { path: path.to_string(), entries })
    }

    pub fn load(path: &str) -> anyhow::Result<ConfigFile> {
        let text = std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("{}: {}", path, e))?;
        ConfigFile::parse(path, &text)
    }

    /// The conventional locations, tried in order, used when no
    /// `-config` was given. A file that is simply absent is not an
    /// error; a file that is present and malformed is.
    pub fn find_default() -> Option<String> {
        let candidates = [
            std::env::var("ARGUS_CONFIG").ok(),
            Some("argus.conf".to_string()),
            Some("/etc/argus/argus.conf".to_string()),
        ];
        candidates.into_iter().flatten().find(|p| Path::new(p).is_file())
    }
}

/// Strips one layer of matching quotes, and any trailing comment on an
/// unquoted value.
fn unquote(s: &str) -> String {
    let b = s.as_bytes();
    if b.len() >= 2 && ((b[0] == b'"' && b[b.len() - 1] == b'"') || (b[0] == b'\'' && b[b.len() - 1] == b'\'')) {
        return s[1..s.len() - 1].to_string();
    }
    // Only unquoted values can carry a trailing comment; inside quotes a
    // '#' is data, which is the case a BPF filter needs.
    match s.find([' ', '\t']).and_then(|_| s.find(['#', ';'])) {
        Some(i) => s[..i].trim().to_string(),
        None => s.to_string(),
    }
}

/// An annotated file showing every setting at its default, written by
/// `-generate-config`.
///
/// Generated from the same help text the binary already carries rather
/// than maintained separately, so it cannot describe an option that no
/// longer exists.
pub fn generate(help_lines: &[(&str, &str, String)]) -> String {
    let mut out = String::with_capacity(4096);
    out.push_str(
        "# ARGUS configuration.\n\
         #\n\
         # Every key is the command-line flag without its leading dash, and a\n\
         # flag on the command line overrides the value here. Section headers\n\
         # are for readability only; the parser ignores them.\n\
         #\n\
         # Keys that may appear more than once: iface, intel, alert-output.\n\n",
    );
    for (key, help, default) in help_lines {
        out.push_str("# ");
        out.push_str(help);
        out.push('\n');
        if default.is_empty() {
            out.push_str(&format!("# {} =\n\n", key));
        } else {
            out.push_str(&format!("# {} = {}\n\n", key, default));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(text: &str) -> Vec<(String, String)> {
        ConfigFile::parse("test.conf", text).unwrap().entries.into_iter().map(|e| (e.key, e.value)).collect()
    }

    #[test]
    fn parses_key_value_pairs_ignoring_comments_and_sections() {
        let got = keys(
            "# a comment\n\
             ; another\n\
             [capture]\n\
             iface = eth0\n\
             rules = rules.txt   # trailing comment\n\
             \n\
             [detection]\n\
             rate-threshold = 500\n",
        );
        assert_eq!(
            got,
            vec![
                ("iface".to_string(), "eth0".to_string()),
                ("rules".to_string(), "rules.txt".to_string()),
                ("rate-threshold".to_string(), "500".to_string()),
            ]
        );
    }

    /// A BPF filter is the reason quoting exists: it contains spaces, and
    /// may legitimately contain a `#`.
    #[test]
    fn quoted_values_keep_spaces_and_hashes() {
        let got = keys("filter = \"not port 22 and not host 10.0.0.1\"\n");
        assert_eq!(got[0].1, "not port 22 and not host 10.0.0.1");
        let got = keys("filter = 'tcp port 80'\n");
        assert_eq!(got[0].1, "tcp port 80");
    }

    #[test]
    fn a_leading_dash_on_a_key_is_tolerated() {
        // Operators copy flags out of their shell history; accepting the
        // dash costs one `trim_start_matches` and saves a confusing
        // "unknown key -iface".
        assert_eq!(keys("-iface = eth0\n")[0].0, "iface");
    }

    #[test]
    fn repeated_keys_are_preserved_in_order() {
        let got = keys("iface = eth0\niface = eth1\n");
        assert_eq!(got.len(), 2, "multi-interface capture needs repeats to survive parsing");
        assert_eq!(got[1].1, "eth1");
    }

    #[test]
    fn a_line_that_is_not_key_value_names_its_line_number() {
        let err = match ConfigFile::parse("test.conf", "iface = eth0\nnonsense\n") {
            Err(e) => e.to_string(),
            Ok(_) => panic!("a malformed line must be refused"),
        };
        assert!(err.contains("test.conf:2"), "errors must point at the line: {}", err);
    }

    #[test]
    fn booleans_accept_the_spellings_people_write() {
        for s in ["true", "yes", "on", "1", "TRUE"] {
            assert!(parse_bool(s).unwrap(), "{}", s);
        }
        for s in ["false", "no", "off", "0"] {
            assert!(!parse_bool(s).unwrap(), "{}", s);
        }
        assert!(parse_bool("maybe").is_err(), "an unrecognised boolean must fail loudly");
    }

    #[test]
    fn generated_config_is_itself_parseable_once_uncommented() {
        let help = vec![("iface", "Interface to monitor", String::new()), ("rate-threshold", "Packets per second", "500".to_string())];
        let text = generate(&help);
        assert!(text.contains("# rate-threshold = 500"));
        // Uncommenting the defaults must yield a valid file.
        let uncommented: String = text.lines().filter(|l| l.starts_with("# ") && l.contains(" = ")).map(|l| format!("{}\n", &l[2..])).collect();
        let parsed = ConfigFile::parse("generated", &uncommented).unwrap();
        assert!(parsed.entries.iter().any(|e| e.key == "rate-threshold" && e.value == "500"));
    }
}
