//! TLS-only GitHub release self-check. Model 1: the repository is the authority.
//!
//! The guest fetches its own release by exact tag over HTTPS, verifies the
//! GitHub-native asset digest, and compares the released measurement with its
//! live SNP measurement. No Sigstore bundles and no pinned certificate roots:
//! trusting GitHub's serving integrity is an explicit property of this design.
//! Provenance attestations remain available to external verifiers; the guest
//! does not re-verify them.
//!
//! Every failure is non-fatal and only affects the printed verdict.

use anyhow::{anyhow, ensure, Result};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{fmt, io::Read, time::Duration};

const API_BASE: &str = "https://api.github.com";
const REPO: &str = "craftsoldier/zns-tee-handoff";
const MEASUREMENT_ASSET: &str = "snp-measurement.txt";
const ASSET_HOSTS: [&str; 3] = [
    "api.github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
];
const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;
const MEASUREMENT_HEX_LEN: usize = 96;

/// Tag injected at build time from the publishing workflow (`RELEASE_TAG`).
pub fn baked_tag() -> Option<&'static str> {
    option_env!("RELEASE_TAG").filter(|tag| !tag.is_empty())
}

/// Parse a release tag `vMAJOR.MINOR.PATCH` into its custody generation
/// (the major version). Legacy `m0-v*`/`m1-v*` tags do not parse.
pub fn parse_generation(tag: &str) -> Option<u32> {
    let rest = tag.strip_prefix('v')?;
    let mut parts = rest.split('.');
    let major = parts.next()?.parse::<u32>().ok()?;
    let minor = parts.next()?.parse::<u32>().ok()?;
    let patch = parts.next()?.parse::<u32>().ok()?;
    if parts.next().is_some() {
        return None;
    }
    let _ = (minor, patch);
    Some(major)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Accept,
    Reject,
    NetworkUnavailable,
    Skipped,
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Status::Accept => "accept",
            Status::Reject => "reject",
            Status::NetworkUnavailable => "network-unavailable",
            Status::Skipped => "skipped",
        };
        f.write_str(text)
    }
}

pub struct SelfCheck {
    pub status: Status,
    pub detail: String,
}

fn reject(detail: impl Into<String>) -> SelfCheck {
    SelfCheck {
        status: Status::Reject,
        detail: detail.into(),
    }
}

fn network(detail: impl Into<String>) -> SelfCheck {
    SelfCheck {
        status: Status::NetworkUnavailable,
        detail: detail.into(),
    }
}

#[derive(Clone)]
pub enum FetchError {
    HttpStatus(u16),
    Transport(String),
}

pub struct Fetched {
    pub body: Vec<u8>,
    pub final_url: String,
}

pub trait ReleaseSource {
    fn get(&self, url: &str, accept: &str) -> Result<Fetched, FetchError>;
}

/// Fetch a release's metadata. `Ok(None)` on 404 (release does not exist).
pub fn fetch_release(source: &dyn ReleaseSource, tag: &str) -> Result<Option<Value>> {
    let url = format!("{API_BASE}/repos/{REPO}/releases/tags/{tag}");
    match source.get(&url, "application/vnd.github+json") {
        Ok(fetched) => {
            let release = serde_json::from_slice(&fetched.body)
                .map_err(|_| anyhow!("malformed release metadata"))?;
            Ok(Some(release))
        }
        Err(FetchError::HttpStatus(404)) => Ok(None),
        Err(FetchError::HttpStatus(code)) => Err(anyhow!("api status {code}")),
        Err(FetchError::Transport(e)) => Err(anyhow!("api unreachable: {e}")),
    }
}

/// Fetch the repository's release listing (newest first per GitHub).
pub fn fetch_release_list(source: &dyn ReleaseSource) -> Result<Vec<Value>> {
    let url = format!("{API_BASE}/repos/{REPO}/releases");
    let fetched = source
        .get(&url, "application/vnd.github+json")
        .map_err(|e| match e {
            FetchError::HttpStatus(code) => anyhow!("api status {code}"),
            FetchError::Transport(t) => anyhow!("api unreachable: {t}"),
        })?;
    serde_json::from_slice(&fetched.body).map_err(|_| anyhow!("malformed release listing"))
}

/// Download one asset from a release listing, enforcing the host allowlist and
/// the GitHub-native digest.
pub fn download_asset_checked(source: &dyn ReleaseSource, asset: &Value) -> Result<Vec<u8>> {
    let Some(digest) = asset["digest"]
        .as_str()
        .and_then(|digest| digest.strip_prefix("sha256:"))
    else {
        return Err(anyhow!("asset digest missing"));
    };
    let Some(url) = asset["url"].as_str() else {
        return Err(anyhow!("asset url missing"));
    };
    let fetched = source
        .get(url, "application/octet-stream")
        .map_err(|e| match e {
            FetchError::HttpStatus(code) => anyhow!("asset status {code}"),
            FetchError::Transport(t) => anyhow!("asset unreachable: {t}"),
        })?;
    let Ok(host) = host_of(&fetched.final_url) else {
        return Err(anyhow!("unexpected asset url"));
    };
    if !ASSET_HOSTS.contains(&host.as_str()) {
        return Err(anyhow!("asset served from unexpected host"));
    }
    if hex::encode(Sha256::digest(&fetched.body)) != digest {
        return Err(anyhow!("asset digest mismatch"));
    }
    Ok(fetched.body)
}

pub struct GitHubRelease {
    agent: ureq::Agent,
}

impl Default for GitHubRelease {
    fn default() -> Self {
        Self {
            agent: ureq::AgentBuilder::new()
                .timeout_connect(Duration::from_secs(5))
                .timeout(Duration::from_secs(20))
                .build(),
        }
    }
}

impl ReleaseSource for GitHubRelease {
    fn get(&self, url: &str, accept: &str) -> Result<Fetched, FetchError> {
        let response = self
            .agent
            .get(url)
            .set("Accept", accept)
            .set("User-Agent", "zns-tee-handoff")
            .call();
        let response = match response {
            Ok(response) => response,
            Err(ureq::Error::Status(code, _)) => return Err(FetchError::HttpStatus(code)),
            Err(ureq::Error::Transport(t)) => return Err(FetchError::Transport(t.to_string())),
        };
        let final_url = response.get_url().to_string();
        let mut body = Vec::new();
        response
            .into_reader()
            .take(MAX_RESPONSE_BYTES + 1)
            .read_to_end(&mut body)
            .map_err(|e| FetchError::Transport(e.to_string()))?;
        if body.len() as u64 > MAX_RESPONSE_BYTES {
            return Err(FetchError::Transport("response too large".into()));
        }
        Ok(Fetched { body, final_url })
    }
}

fn host_of(url: &str) -> Result<String> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| anyhow!("not https"))?;
    let authority = rest.split('/').next().unwrap_or_default();
    let host_port = authority.rsplit('@').next().unwrap_or(authority);
    let host = host_port.split(':').next().unwrap_or_default();
    ensure!(!host.is_empty(), "no host in url");
    Ok(host.to_ascii_lowercase())
}

/// Run the full release self-check against `source`.
///
/// `live_measurement` comes from the SNP report; `tag` overrides the baked-in
/// release tag (used by tests and local runs).
pub fn self_check(
    live_measurement: Option<[u8; 48]>,
    tag: Option<&str>,
    source: &dyn ReleaseSource,
) -> SelfCheck {
    let tag = match tag {
        Some(tag) => tag,
        None => match baked_tag() {
            Some(tag) => tag,
            None => {
                return SelfCheck {
                    status: Status::Skipped,
                    detail: "no release tag baked into this build".into(),
                }
            }
        },
    };
    if parse_generation(tag).is_none() {
        return reject("tag does not match vX.Y.Z");
    }
    let release_url = format!("{API_BASE}/repos/{REPO}/releases/tags/{tag}");
    let fetched = match source.get(&release_url, "application/vnd.github+json") {
        Ok(fetched) => fetched,
        Err(FetchError::Transport(e)) => return network(format!("api unreachable: {e}")),
        Err(FetchError::HttpStatus(404)) => return reject("release not found"),
        Err(FetchError::HttpStatus(code)) => return reject(format!("api status {code}")),
    };
    let release: Value = match serde_json::from_slice(&fetched.body) {
        Ok(release) => release,
        Err(_) => return reject("malformed release metadata"),
    };
    if release["tag_name"].as_str() != Some(tag) {
        return reject("api returned a different tag");
    }
    let Some(assets) = release["assets"].as_array() else {
        return reject("release has no assets");
    };
    let Some(asset) = assets
        .iter()
        .find(|asset| asset["name"].as_str() == Some(MEASUREMENT_ASSET))
    else {
        return reject("measurement asset missing from release");
    };
    let Some(digest) = asset["digest"]
        .as_str()
        .and_then(|digest| digest.strip_prefix("sha256:"))
    else {
        return reject("asset digest missing");
    };
    let Some(asset_url) = asset["url"].as_str() else {
        return reject("asset url missing");
    };
    let fetched = match source.get(asset_url, "application/octet-stream") {
        Ok(fetched) => fetched,
        Err(FetchError::Transport(e)) => return network(format!("asset unreachable: {e}")),
        Err(FetchError::HttpStatus(code)) => return reject(format!("asset status {code}")),
    };
    let Ok(host) = host_of(&fetched.final_url) else {
        return reject("unexpected asset url");
    };
    if !ASSET_HOSTS.contains(&host.as_str()) {
        return reject("asset served from unexpected host");
    }
    if hex::encode(Sha256::digest(&fetched.body)) != digest {
        return reject("asset digest mismatch");
    }
    let Ok(text) = std::str::from_utf8(&fetched.body) else {
        return reject("measurement file is not utf-8");
    };
    let measurement_hex = text.trim();
    if measurement_hex.len() != MEASUREMENT_HEX_LEN
        || !measurement_hex.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return reject("malformed measurement file");
    }
    let Ok(measurement) = hex::decode(measurement_hex) else {
        return reject("malformed measurement file");
    };
    let Ok(measurement) = <[u8; 48]>::try_from(measurement) else {
        return reject("malformed measurement file");
    };
    match live_measurement {
        Some(live) if live == measurement => SelfCheck {
            status: Status::Accept,
            detail: format!("tag {tag} measurement matches this guest"),
        },
        Some(_) => reject("released measurement does not match this guest"),
        None => SelfCheck {
            status: Status::Skipped,
            detail: "no live measurement available".into(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::parse_generation;

    #[test]
    fn generation_is_the_major_version() {
        assert_eq!(parse_generation("v1.0.0"), Some(1));
        assert_eq!(parse_generation("v2.5.0"), Some(2));
    }

    #[test]
    fn legacy_and_malformed_tags_do_not_parse() {
        assert_eq!(parse_generation("m0-v0.5.0"), None);
        assert_eq!(parse_generation("m1-v0.4.0"), None);
        assert_eq!(parse_generation("v1.0"), None);
        assert_eq!(parse_generation("v1.0.0.0"), None);
        assert_eq!(parse_generation("v1.0.0-rc1"), None);
        assert_eq!(parse_generation("custody-v1"), None);
    }

    use super::*;
    use std::cell::Cell;

    const FIXTURE: &str = include_str!("../tests/fixtures/api-release-v1.0.0.json");
    const MEASUREMENT_HEX: &str = "c0ac09eb9957dbee62a4479d376ee5a2e889afd446dc857bdbfc7d1e7e547574e57f55c9ec79b98edad0fc82c1d8ea18";
    const TAG: &str = "v1.0.0";

    fn measurement() -> [u8; 48] {
        hex::decode(MEASUREMENT_HEX).unwrap().try_into().unwrap()
    }

    fn fixture() -> Value {
        serde_json::from_str(FIXTURE).unwrap()
    }

    struct FnSource {
        release: Result<Value, FetchError>,
        asset_body: Result<Vec<u8>, FetchError>,
        asset_host: &'static str,
        called: Cell<u32>,
    }

    impl FnSource {
        fn real() -> Self {
            Self {
                release: Ok(fixture()),
                asset_body: Ok({
                    let mut body = MEASUREMENT_HEX.as_bytes().to_vec();
                    body.push(b'\n');
                    body
                }),
                asset_host: "objects.githubusercontent.com",
                called: Cell::new(0),
            }
        }

        fn with_release_error(error: FetchError) -> Self {
            Self {
                release: Err(error),
                asset_body: Ok(Vec::new()),
                asset_host: "objects.githubusercontent.com",
                called: Cell::new(0),
            }
        }
    }

    impl ReleaseSource for FnSource {
        fn get(&self, url: &str, _accept: &str) -> Result<Fetched, FetchError> {
            self.called.set(self.called.get() + 1);
            if url.contains("/releases/tags/") {
                let body = serde_json::to_vec(&self.release.clone()?).unwrap();
                return Ok(Fetched {
                    body,
                    final_url: url.to_string(),
                });
            }
            if url.contains("/releases/assets/") {
                let body = match &self.asset_body {
                    Ok(body) => body.clone(),
                    Err(e) => return Err(e.clone()),
                };
                return Ok(Fetched {
                    body,
                    final_url: format!("https://{}/blob", self.asset_host),
                });
            }
            Err(FetchError::HttpStatus(500))
        }
    }

    #[test]
    fn accept_when_release_matches_live_report() {
        let source = FnSource::real();
        let check = self_check(Some(measurement()), Some(TAG), &source);
        assert_eq!(check.status, Status::Accept, "{}", check.detail);
        assert_eq!(source.called.get(), 2);
    }

    #[test]
    fn mismatching_live_report_is_rejected() {
        let mut live = measurement();
        live[0] ^= 1;
        let check = self_check(Some(live), Some(TAG), &FnSource::real());
        assert_eq!(check.status, Status::Reject);
        assert!(check.detail.contains("does not match"));
    }

    #[test]
    fn tampered_asset_bytes_are_rejected() {
        let mut source = FnSource::real();
        source.asset_body = Ok({
            let mut body = MEASUREMENT_HEX.as_bytes().to_vec();
            body.push(b'\n');
            body
        });
        if let Ok(body) = &mut source.asset_body {
            body[0] ^= 1;
        }
        let check = self_check(Some(measurement()), Some(TAG), &source);
        assert_eq!(check.status, Status::Reject);
        assert!(check.detail.contains("digest mismatch"));
    }

    #[test]
    fn unexpected_asset_host_is_rejected() {
        let mut source = FnSource::real();
        source.asset_host = "evil.example";
        let check = self_check(Some(measurement()), Some(TAG), &source);
        assert_eq!(check.status, Status::Reject);
        assert!(check.detail.contains("unexpected host"));
    }

    #[test]
    fn different_tag_in_response_is_rejected() {
        let mut source = FnSource::real();
        source.release = Ok({
            let mut value = fixture();
            value["tag_name"] = Value::String("v1.1.0".into());
            value
        });
        let check = self_check(Some(measurement()), Some(TAG), &source);
        assert_eq!(check.status, Status::Reject);
        assert!(check.detail.contains("different tag"));
    }

    #[test]
    fn missing_measurement_asset_is_rejected() {
        let mut source = FnSource::real();
        source.release = Ok({
            let mut value = fixture();
            value["assets"]
                .as_array_mut()
                .unwrap()
                .retain(|asset| asset["name"].as_str() != Some(MEASUREMENT_ASSET));
            value
        });
        let check = self_check(Some(measurement()), Some(TAG), &source);
        assert_eq!(check.status, Status::Reject);
        assert!(check.detail.contains("missing"));
    }

    #[test]
    fn missing_asset_digest_is_rejected() {
        let mut source = FnSource::real();
        source.release = Ok({
            let mut value = fixture();
            for asset in value["assets"].as_array_mut().unwrap() {
                if asset["name"].as_str() == Some(MEASUREMENT_ASSET) {
                    asset["digest"] = Value::Null;
                }
            }
            value
        });
        let check = self_check(Some(measurement()), Some(TAG), &source);
        assert_eq!(check.status, Status::Reject);
        assert!(check.detail.contains("digest missing"));
    }

    #[test]
    fn malformed_measurement_file_is_rejected() {
        use sha2::{Digest, Sha256};
        let body = b"not-a-measurement\n".to_vec();
        let mut source = FnSource::real();
        source.asset_body = Ok(body.clone());
        source.release = Ok({
            let mut value = fixture();
            let digest = hex::encode(Sha256::digest(&body));
            for asset in value["assets"].as_array_mut().unwrap() {
                if asset["name"].as_str() == Some(MEASUREMENT_ASSET) {
                    asset["digest"] = Value::String(format!("sha256:{digest}"));
                }
            }
            value
        });
        let check = self_check(Some(measurement()), Some(TAG), &source);
        assert_eq!(check.status, Status::Reject);
        assert!(check.detail.contains("malformed"));
    }

    #[test]
    fn tag_prefix_is_enforced_without_network() {
        let source = FnSource::real();
        let check = self_check(Some(measurement()), Some("evil-v1"), &source);
        assert_eq!(check.status, Status::Reject);
        assert_eq!(source.called.get(), 0);
    }

    #[test]
    fn missing_release_is_rejected() {
        let check = self_check(
            Some(measurement()),
            Some(TAG),
            &FnSource::with_release_error(FetchError::HttpStatus(404)),
        );
        assert_eq!(check.status, Status::Reject);
        assert!(check.detail.contains("not found"));
    }

    #[test]
    fn transport_failure_is_network_unavailable() {
        let check = self_check(
            Some(measurement()),
            Some(TAG),
            &FnSource::with_release_error(FetchError::Transport("dns failure".into())),
        );
        assert_eq!(check.status, Status::NetworkUnavailable);
    }

    #[test]
    fn missing_tag_is_skipped() {
        let source = FnSource::real();
        let check = self_check(Some(measurement()), None, &source);
        assert_eq!(check.status, Status::Skipped);
        assert_eq!(source.called.get(), 0);
    }
}
