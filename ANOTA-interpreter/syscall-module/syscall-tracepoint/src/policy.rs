use anyhow::{bail, ensure, Context, Result};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    net::ToSocketAddrs,
    path::{Component, Path, PathBuf},
};
use syscall_tracepoint_common::{syscall_name, Event, PATH_LEN};

pub type Rules = (Vec<(u16, String)>, Vec<(u16, String)>);

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub version: u32,
    pub action: String,
    pub pid: u32,
    #[serde(default)]
    pub blocked: Vec<String>,
    #[serde(default)]
    pub allowed: Vec<String>,
    #[serde(default)]
    pub operations: BTreeMap<String, Rules>,
}

#[derive(Clone, Debug)]
struct Pattern {
    kind: u16,
    value: String,
}

#[derive(Clone, Debug, Default)]
pub struct Policy {
    blocked: Vec<String>,
    allowed: Vec<String>,
    operations: Vec<(String, Vec<Pattern>, Vec<Pattern>)>,
}

#[derive(Default, Debug)]
pub struct Observation {
    pub scopes: Vec<String>,
    pub paths: Vec<String>,
    pub ips: Vec<String>,
    pub protocols: Vec<String>,
    pub incomplete: Vec<String>,
}

pub fn normalize(path: &Path) -> PathBuf {
    let mut result = PathBuf::new();
    for part in path.components() {
        match part {
            Component::ParentDir => {
                result.pop();
            }
            Component::CurDir => {}
            other => result.push(other.as_os_str()),
        }
    }
    result
}

fn name(value: &str) -> Result<String> {
    let upper = value.to_ascii_uppercase();
    let upper = if upper == "EXECV" {
        "EXECVE".into()
    } else {
        upper
    };
    ensure!(
        matches!(
            upper.as_str(),
            "FILE" | "NETWORK" | "READ" | "WRITE" | "OPEN"
        ) || syscall_tracepoint_common::syscalls::NAMES
            .iter()
            .any(|(_, s)| *s == upper)
            || upper
                .strip_prefix("SYSCALL_")
                .is_some_and(|s| s.parse::<u64>().is_ok()),
        "unknown syscall or class: {value}"
    );
    Ok(upper)
}

fn patterns(input: &[(u16, String)], cwd: &Path) -> Result<Vec<Pattern>> {
    let mut result = Vec::new();
    for (encoded, value) in input {
        let kind = encoded & 0xff;
        ensure!(
            (1..=5).contains(&kind) && encoded & !0x1ff == 0,
            "invalid policy kind {encoded}"
        );
        ensure!(
            !value.is_empty() && !value.contains('\0') && value.len() < PATH_LEN,
            "empty, NUL-containing, or overlong policy value"
        );
        if kind == 3 {
            // DNS names are not carried by connect(). Resolve an exact name at
            // installation, then match its addresses. Never guess wildcard DNS.
            ensure!(
                !value.contains('*'),
                "wildcard DOMAIN is not observable in syscalls; use IP patterns"
            );
            let addresses = (value.as_str(), 0)
                .to_socket_addrs()
                .context("resolve DOMAIN")?;
            let before = result.len();
            for addr in addresses {
                result.push(Pattern {
                    kind: 4,
                    value: addr.ip().to_string(),
                });
            }
            ensure!(result.len() > before, "DOMAIN has no IP addresses");
        } else {
            let mut value = value.clone();
            if kind == 1 || kind == 2 {
                let path = Path::new(&value);
                value = normalize(&if path.is_absolute() {
                    path.to_owned()
                } else {
                    cwd.join(path)
                })
                .to_string_lossy()
                .into_owned();
                if kind == 2 && !value.ends_with('/') {
                    value.push('/');
                }
            } else if kind == 4 {
                value = value.to_ascii_lowercase();
            }
            result.push(Pattern { kind, value });
        }
    }
    Ok(result)
}

impl Policy {
    pub fn compile(request: &Request, cwd: &Path) -> Result<Self> {
        ensure!(request.version == 1, "unsupported protocol version");
        ensure!(request.pid > 0, "pid must be positive");
        ensure!(
            request.blocked.len()
                + request.allowed.len()
                + request
                    .operations
                    .values()
                    .map(|(a, b)| a.len() + b.len())
                    .sum::<usize>()
                <= 4096,
            "too many policy rules"
        );
        let mut operations = Vec::new();
        for (scope, (allow, block)) in &request.operations {
            operations.push((name(scope)?, patterns(allow, cwd)?, patterns(block, cwd)?));
        }
        Ok(Self {
            blocked: request
                .blocked
                .iter()
                .map(|s| name(s))
                .collect::<Result<_>>()?,
            allowed: request
                .allowed
                .iter()
                .map(|s| name(s))
                .collect::<Result<_>>()?,
            operations,
        })
    }

    pub fn evaluate(&self, event: &Event, observation: &Observation) -> Vec<String> {
        let raw = syscall_name(event.syscall)
            .map(str::to_owned)
            .unwrap_or_else(|| format!("SYSCALL_{}", event.syscall));
        let mut names = observation.scopes.clone();
        names.push(raw.clone());
        let mut reasons = Vec::new();
        if self.blocked.iter().any(|n| names.contains(n)) {
            reasons.push("syscall blocked".to_string());
        } else if !self.allowed.is_empty() && !self.allowed.iter().any(|n| names.contains(n)) {
            reasons.push("syscall not in allow list".to_string());
        }
        for (scope, allow, block) in &self.operations {
            if !names.contains(scope) {
                continue;
            }
            for (kind, values) in [
                (1, &observation.paths),
                (4, &observation.ips),
                (5, &observation.protocols),
            ] {
                let relevant = |p: &&Pattern| p.kind == kind || (kind == 1 && p.kind == 2);
                let allowed: Vec<_> = allow.iter().filter(relevant).collect();
                let blocked: Vec<_> = block.iter().filter(relevant).collect();
                for value in values {
                    if blocked.iter().any(|p| p.matches(value)) {
                        reasons.push(format!("{scope} target blocked: {value:?}"));
                    } else if !allowed.is_empty() && !allowed.iter().any(|p| p.matches(value)) {
                        reasons.push(format!("{scope} target not in allow list: {value:?}"));
                    }
                }
            }
        }
        reasons
            .into_iter()
            .map(|reason| {
                format!(
                    "ANOTA_SYSCALL violation: pid={} tid={} {} ret={} ({})",
                    event.pid, event.tid, raw, event.result, reason
                )
            })
            .collect()
    }
}

impl Pattern {
    fn matches(&self, text: &str) -> bool {
        if self.kind == 2 && !self.value.contains('*') {
            text == self.value.trim_end_matches('/') || text.starts_with(&self.value)
        } else {
            wildcard(&self.value, text)
        }
    }
}

/// Linear-space wildcard matching. '*' is the only metacharacter, matching
/// the annotation frontend (including across '/' in path patterns).
fn wildcard(pattern: &str, value: &str) -> bool {
    let (p, v) = (pattern.as_bytes(), value.as_bytes());
    let (mut pi, mut vi, mut star, mut retry) = (0, 0, None, 0);
    while vi < v.len() {
        if pi < p.len() && p[pi] == b'*' {
            star = Some(pi);
            pi += 1;
            retry = vi;
        } else if pi < p.len() && p[pi] == v[vi] {
            pi += 1;
            vi += 1;
        } else if let Some(s) = star {
            retry += 1;
            vi = retry;
            pi = s + 1;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

pub fn validate_request(request: &Request) -> Result<()> {
    ensure!(
        request.version == 1 && request.pid > 0,
        "invalid version or pid"
    );
    match request.action.as_str() {
        "replace" | "stop" => Ok(()),
        _ => bail!("unknown action: {}", request.action),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> Request {
        Request {
            version: 1,
            action: "replace".into(),
            pid: 42,
            ..Request::default()
        }
    }
    fn event(nr: u64) -> Event {
        let mut e = Event::empty();
        e.syscall = nr;
        e.pid = 42;
        e
    }
    #[test]
    fn file_group_directory_boundary_and_deny_precedence() {
        let mut r = request();
        r.operations.insert(
            "FILE".into(),
            (
                vec![(2, "/safe/".into())],
                vec![(257, "/safe/*.key".into())],
            ),
        );
        let p = Policy::compile(&r, Path::new("/tmp")).unwrap();
        for (path, violations) in [("/safe/a", 0), ("/safe2/a", 1), ("/safe/a.key", 1)] {
            let o = Observation {
                scopes: vec!["FILE".into()],
                paths: vec![path.into()],
                ..Default::default()
            };
            assert_eq!(p.evaluate(&event(257), &o).len(), violations);
        }
    }
    #[test]
    fn raw_syscall_alias_and_allow_list() {
        let mut r = request();
        r.blocked = vec!["execv".into()];
        let p = Policy::compile(&r, Path::new("/")).unwrap();
        let o = Observation {
            scopes: vec!["EXECVE".into()],
            ..Default::default()
        };
        assert_eq!(p.evaluate(&event(322), &o).len(), 1);
        r.blocked.clear();
        r.allowed = vec!["getpid".into()];
        let p = Policy::compile(&r, Path::new("/")).unwrap();
        assert!(p.evaluate(&event(39), &Observation::default()).is_empty());
        assert_eq!(p.evaluate(&event(110), &Observation::default()).len(), 1);
    }
    #[test]
    fn network_ip_and_protocol_are_independent_constraints() {
        let mut r = request();
        r.operations.insert(
            "NETWORK".into(),
            (vec![(260, "127.*".into()), (5, "6".into())], vec![]),
        );
        let p = Policy::compile(&r, Path::new("/")).unwrap();
        let o = Observation {
            scopes: vec!["NETWORK".into()],
            ips: vec!["127.0.0.1".into()],
            protocols: vec!["17".into()],
            ..Default::default()
        };
        assert_eq!(p.evaluate(&event(42), &o).len(), 1);
    }
    #[test]
    fn invalid_rules_are_rejected_and_relative_paths_are_anchored() {
        let mut r = request();
        r.blocked = vec!["typo".into()];
        assert!(Policy::compile(&r, Path::new("/")).is_err());
        r.blocked.clear();
        r.operations.insert(
            "CONNECT".into(),
            (vec![], vec![(3, "*.example.com".into())]),
        );
        assert!(Policy::compile(&r, Path::new("/")).is_err());
        r.operations.clear();
        r.operations
            .insert("READ".into(), (vec![], vec![(1, "../secret".into())]));
        let p = Policy::compile(&r, Path::new("/tmp/work")).unwrap();
        let o = Observation {
            scopes: vec!["READ".into()],
            paths: vec!["/tmp/secret".into()],
            ..Default::default()
        };
        assert_eq!(p.evaluate(&event(0), &o).len(), 1);
    }
    #[test]
    fn pattern_matching() {
        assert!(wildcard("a*b*c", "abbbcc"));
        assert!(!wildcard("/safe/*", "/safe2/a"));
        assert!(wildcard("*", ""));
        assert!(wildcard("a*", "a"));
    }
}
