fn main() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    if let Err(e) = rt.block_on(edgeshield_cli::cli::run()) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
