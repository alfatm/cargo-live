//! A tiny HTTP/1.1 server for tests: static files under path prefixes that
//! require Basic or token authentication, plus optional dynamic handlers.
//! Every request is answered with `Connection: close`.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use base64::Engine;

#[derive(Clone)]
pub enum Auth {
    /// `Authorization: Basic base64(user:pass)`.
    Basic(String, String),
    /// `Authorization: <token>` (Cargo sends registry tokens verbatim).
    Token(String),
}

pub struct Request {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

pub struct Response {
    pub status: u16,
    pub content_type: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn new(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            content_type: "text/plain".into(),
            headers: Vec::new(),
            body: body.into(),
        }
    }

    pub fn json(status: u16, value: serde_json::Value) -> Self {
        Self {
            content_type: "application/json".into(),
            ..Self::new(status, value.to_string())
        }
    }
}

type Handler = Box<dyn Fn(&Request) -> Option<Response> + Send + Sync>;

struct Route {
    prefix: String,
    root: PathBuf,
    auth: Auth,
}

#[derive(Default)]
struct State {
    routes: Vec<Route>,
    handlers: Vec<Handler>,
    /// `"<METHOD> <path> -> <status>"` for each request.
    log: Vec<String>,
}

#[derive(Clone)]
pub struct Server {
    pub port: u16,
    state: Arc<Mutex<State>>,
}

impl Server {
    pub fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let state = Arc::new(Mutex::new(State::default()));
        let shared = state.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let state = shared.clone();
                std::thread::spawn(move || {
                    let _ = handle(stream, &state);
                });
            }
        });
        Server { port, state }
    }

    pub fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
    }

    pub fn host(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }

    /// Serves files of `root` under `prefix` (e.g. `/git/acme/`).
    pub fn serve_dir(&self, prefix: &str, root: PathBuf, auth: Auth) {
        self.state.lock().unwrap().routes.push(Route {
            prefix: prefix.into(),
            root,
            auth,
        });
    }

    pub fn handle(&self, handler: impl Fn(&Request) -> Option<Response> + Send + Sync + 'static) {
        self.state.lock().unwrap().handlers.push(Box::new(handler));
    }

    pub fn log(&self) -> Vec<String> {
        self.state.lock().unwrap().log.clone()
    }
}

fn authorized(auth: &Auth, header: Option<&String>) -> bool {
    match (auth, header) {
        (Auth::Basic(user, pass), Some(h)) => {
            let expected =
                base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
            h == &format!("Basic {expected}")
        }
        (Auth::Token(token), Some(h)) => h == token,
        _ => false,
    }
}

fn handle(stream: TcpStream, state: &Mutex<State>) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or("").to_owned();
    let target = parts.next().unwrap_or("").to_owned();
    let mut headers = HashMap::new();
    loop {
        let mut h = String::new();
        if reader.read_line(&mut h)? == 0 || h.trim().is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_owned());
        }
    }
    let len: usize = headers
        .get("content-length")
        .and_then(|l| l.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0; len];
    reader.read_exact(&mut body)?;
    let path = target.split('?').next().unwrap_or("").to_owned();
    let request = Request {
        method,
        path,
        headers,
        body,
    };
    let response = respond(&request, state);
    state.lock().unwrap().log.push(format!(
        "{} {} -> {}",
        request.method, request.path, response.status
    ));
    let mut out = stream;
    let mut head = format!(
        "HTTP/1.1 {} X\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
        response.status,
        response.content_type,
        response.body.len()
    );
    for (k, v) in &response.headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    out.write_all(head.as_bytes())?;
    out.write_all(&response.body)?;
    out.flush()
}

fn respond(request: &Request, state: &Mutex<State>) -> Response {
    let state = state.lock().unwrap();
    for handler in &state.handlers {
        if let Some(r) = handler(request) {
            return r;
        }
    }
    let Some(route) = state
        .routes
        .iter()
        .filter(|r| request.path.starts_with(&r.prefix))
        .max_by_key(|r| r.prefix.len())
    else {
        return Response::new(404, "no route");
    };
    if !authorized(&route.auth, request.headers.get("authorization")) {
        let mut r = Response::new(401, "unauthorized");
        if let Auth::Basic(..) = route.auth {
            r.headers
                .push(("WWW-Authenticate".into(), "Basic realm=\"test\"".into()));
        }
        return r;
    }
    let rel = &request.path[route.prefix.len()..];
    if rel.split('/').any(|c| c == "..") {
        return Response::new(400, "bad path");
    }
    match std::fs::read(route.root.join(rel)) {
        Ok(data) => Response::new(200, data),
        Err(_) => Response::new(404, "not found"),
    }
}
