#![forbid(unsafe_code)]

#[cfg(any(unix, windows))]
#[tokio::main]
async fn main() {
    let locked = std::env::args().nth(1).as_deref() == Some("--locked");
    let result = if locked {
        envault::daemon::run_locked().await
    } else {
        envault::daemon::run_from_stdio().await
    };
    if let Err(error) = result {
        eprintln!("envaultd: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(any(unix, windows)))]
fn main() {
    eprintln!("envaultd: runtime support is available on Linux, macOS, and Windows only");
    std::process::exit(1);
}
