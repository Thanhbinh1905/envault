#![forbid(unsafe_code)]

#[cfg(any(unix, windows))]
#[tokio::main]
async fn main() {
    if let Err(error) = envault::daemon::run_from_stdio().await {
        eprintln!("envaultd: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(any(unix, windows)))]
fn main() {
    eprintln!("envaultd: runtime support is available on Linux, macOS, and Windows only");
    std::process::exit(1);
}
