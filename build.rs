fn main() -> Result<(), Box<dyn std::error::Error>> {
    prost_build::compile_protos(
        &["proto/SessionProtos.proto", "proto/WebSocketResources.proto"],
        &["proto/"],
    )?;

    println!("cargo:rerun-if-changed=assets/session.rc");
    println!("cargo:rerun-if-changed=assets/session.ico");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let out_dir = std::path::PathBuf::from(std::env::var_os("OUT_DIR").ok_or("OUT_DIR missing")?);
        let object = out_dir.join("session-icon.o");
        let windres = std::env::var("WINDRES")
            .unwrap_or_else(|_| "x86_64-w64-mingw32-windres".to_owned());
        let status = std::process::Command::new(windres)
            .args(["assets/session.rc", "-O", "coff", "-o"])
            .arg(&object)
            .status()?;
        if !status.success() {
            return Err("windres failed to compile Session icon resource".into());
        }
        println!("cargo:rustc-link-arg-bins={}", object.display());
    }
    Ok(())
}
