// Test helpers shared across integration tests.
//
// `MockVault` is a stripped-down HTTP server that handles just enough of the
// Vault API to exercise vaultpow's HTTP-direct probes — token lookup-self,
// token renew-self, sys/health. It avoids pulling in wiremock/mockito (and
// their async runtimes) in favour of a tiny std::net implementation that
// runs on a dedicated thread per server instance.
//
// `#[allow(dead_code)]` because each integration test binary `mod common;`s
// this file independently and only uses a subset of the helpers; without the
// allow, each binary warns about the parts it doesn't touch.

#![allow(dead_code)]

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

use assert_cmd::cargo::CommandCargoExt;
use std::process::Command;
use tempfile::TempDir;

/// One canned response keyed by HTTP method + path.
#[derive(Clone)]
pub struct CannedResponse {
    pub status: u16,
    pub body: String,
}

impl CannedResponse {
    pub fn ok(body: impl Into<String>) -> Self {
        Self {
            status: 200,
            body: body.into(),
        }
    }
    pub fn forbidden() -> Self {
        Self {
            status: 403,
            body: r#"{"errors":["permission denied"]}"#.into(),
        }
    }
}

#[derive(Clone, Default)]
struct State {
    /// (method, path) → response
    routes: HashMap<(String, String), CannedResponse>,
    /// Captured requests for assertions.
    requests: Vec<RecordedRequest>,
    /// If set, every request returns this regardless of routing.
    fallback: Option<CannedResponse>,
}

#[derive(Clone, Debug)]
pub struct RecordedRequest {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: String,
}

pub struct MockVault {
    pub addr: String,
    state: Arc<Mutex<State>>,
    _shutdown_listener: TcpListener,
}

impl MockVault {
    pub fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind 0");
        let addr = listener.local_addr().unwrap();
        let state: Arc<Mutex<State>> = Arc::new(Mutex::new(State::default()));
        let st = state.clone();

        // The accept loop runs until the listener is dropped (which happens
        // when MockVault is dropped — we keep a clone in `_shutdown_listener`).
        let listener_clone = listener.try_clone().expect("clone listener");
        thread::spawn(move || {
            for stream in listener_clone.incoming() {
                let Ok(stream) = stream else {
                    return; // listener closed
                };
                let st = st.clone();
                thread::spawn(move || {
                    let _ = handle_conn(stream, st);
                });
            }
        });

        MockVault {
            addr: format!("http://127.0.0.1:{}", addr.port()),
            state,
            _shutdown_listener: listener,
        }
    }

    pub fn route(&self, method: &str, path: &str, resp: CannedResponse) -> &Self {
        self.state
            .lock()
            .unwrap()
            .routes
            .insert((method.to_string(), path.to_string()), resp);
        self
    }

    /// Convenience for the most common health probe.
    pub fn route_health_ok(&self) -> &Self {
        self.route(
            "GET",
            "/v1/sys/health",
            CannedResponse::ok(r#"{"initialized":true,"sealed":false}"#),
        )
    }

    pub fn requests(&self) -> Vec<RecordedRequest> {
        self.state.lock().unwrap().requests.clone()
    }
}

fn handle_conn(mut stream: TcpStream, state: Arc<Mutex<State>>) -> std::io::Result<()> {
    stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    let mut reader = BufReader::new(stream.try_clone()?);

    // Request line
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 2 {
        return Ok(());
    }
    let method = parts[0].to_string();
    let path = parts[1].to_string();

    // Headers
    let mut headers = HashMap::new();
    let mut content_length = 0usize;
    loop {
        let mut h = String::new();
        if reader.read_line(&mut h)? == 0 {
            break;
        }
        if h == "\r\n" || h == "\n" {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            let k = k.trim().to_lowercase();
            let v = v.trim().to_string();
            if k == "content-length" {
                content_length = v.parse().unwrap_or(0);
            }
            headers.insert(k, v);
        }
    }

    // Body
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body)?;
    }
    let body_str = String::from_utf8_lossy(&body).into_owned();

    // Lookup + record.
    let resp = {
        let mut st = state.lock().unwrap();
        st.requests.push(RecordedRequest {
            method: method.clone(),
            path: path.clone(),
            headers: headers.clone(),
            body: body_str,
        });
        st.routes
            .get(&(method.clone(), path.clone()))
            .cloned()
            .or_else(|| st.fallback.clone())
            .unwrap_or(CannedResponse {
                status: 404,
                body: format!(r#"{{"error":"no route for {method} {path}"}}"#),
            })
    };

    let status_text = match resp.status {
        200 => "OK",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "Status",
    };
    let response = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        resp.status,
        status_text,
        resp.body.len(),
        resp.body,
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()?;
    Ok(())
}

/// One-stop fixture for tests that spawn the binary against a tempdir-backed
/// config file. The TempDir is owned and dropped with the fixture.
pub struct CliFixture {
    pub config_dir: TempDir,
    pub config_path: std::path::PathBuf,
}

impl Default for CliFixture {
    fn default() -> Self {
        Self::new()
    }
}

impl CliFixture {
    pub fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vaultctx.yaml");
        CliFixture {
            config_dir: dir,
            config_path: path,
        }
    }

    /// `assert_cmd::Command` would not let us scope env vars cleanly when the
    /// binary checks `HOME`, so we use std::process::Command directly via the
    /// `cargo_bin` extension.
    pub fn cmd(&self) -> Command {
        let mut cmd = Command::cargo_bin("vaultpow").expect("locate vaultpow binary");
        cmd.env("VAULTCTX_FILE", &self.config_path);
        // Make sure HOME doesn't leak into config_path() if VAULTCTX_FILE is
        // somehow ignored.
        cmd.env("HOME", self.config_dir.path());
        // Don't inherit any ambient Vault env from the developer's shell.
        cmd.env_remove("VAULT_ADDR");
        cmd.env_remove("VAULT_TOKEN");
        cmd.env_remove("VAULT_NAMESPACE");
        cmd
    }
}
