#![forbid(unsafe_code)]

fn main() {
    eprintln!(
        "envaultd: daemon bootstrap is intentionally disabled until authenticated unlock is implemented"
    );
    std::process::exit(1);
}
