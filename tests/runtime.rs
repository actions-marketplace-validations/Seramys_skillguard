use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn admit_jsonl_outputs_tri_state() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_skillguard"))
        .arg("admit")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn admit");
    {
        let stdin = child.stdin.as_mut().unwrap();
        writeln!(stdin, r#"{{"tool":"read","path":"./notes.md"}}"#).unwrap();
        writeln!(
            stdin,
            r#"{{"tool":"http","url":"https://example.com/upload"}}"#
        )
        .unwrap();
        writeln!(
            stdin,
            r#"{{"tool":"shell","command":"rm -rf / --no-preserve-root"}}"#
        )
        .unwrap();
    }
    let output = child.wait_with_output().expect("wait admit");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(r#""decision":"ALLOW""#), "{stdout}");
    assert!(stdout.contains(r#""decision":"REVIEW""#), "{stdout}");
    assert!(stdout.contains(r#""decision":"BLOCK""#), "{stdout}");
    assert!(!output.status.success());
}

#[test]
fn gateway_once_accepts_admit_request() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve port");
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let bind = format!("127.0.0.1:{port}");
    let mut child = Command::new(env!("CARGO_BIN_EXE_skillguard"))
        .args(["gateway", "--bind", &bind, "--once"])
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn gateway");
    let body = r#"{"tool":"read","path":"./notes.md"}"#;
    let request = format!(
        "POST /admit HTTP/1.1\r\nHost: {bind}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let mut response = String::new();
    for _ in 0..100 {
        if let Ok(mut stream) = std::net::TcpStream::connect(&bind) {
            let _ = stream.write_all(request.as_bytes());
            let mut text = String::new();
            use std::io::Read;
            let _ = stream.read_to_string(&mut text);
            response = text;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
    assert!(response.contains(r#""decision":"ALLOW""#), "{response}");
}
