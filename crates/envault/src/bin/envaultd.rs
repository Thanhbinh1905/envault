#![forbid(unsafe_code)]

#[cfg(unix)]
#[tokio::main]
async fn main() {
    if let Err(error) = envault::daemon::run_from_stdio().await {
        eprintln!("envaultd: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(unix))]
fn main() {
    eprintln!("envaultd: runtime support is available on Linux and macOS in this release phase");
    std::process::exit(1);
}
