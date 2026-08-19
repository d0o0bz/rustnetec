use anyhow::Result;
use std::{env, fs::File, path::PathBuf};

fn main() -> Result<()> {
    // Generate shell completions and manpage
    generate_assets()?;

    // Add library search paths for cross-compilation
    setup_cross_compilation_libs();

    // eBPF program compilation now lives in the rustnet-host crate's build.rs.

    #[cfg(target_os = "windows")]
    download_windows_npcap_sdk()?;

    // rustnetec: 构建期把 rustnetec.ico 嵌入 exe 资源（图标显示）
    #[cfg(target_os = "windows")]
    embed_windows_icon()?;

    println!("cargo:rerun-if-changed=src/cli.rs");

    Ok(())
}

include!("src/cli.rs");

fn setup_cross_compilation_libs() {
    let target = env::var("TARGET").unwrap_or_default();
    let host = env::var("HOST").unwrap_or_default();

    // Only apply hard-coded multiarch lib paths when actually cross-compiling.
    // On native builds (e.g. Homebrew on Linux arm64) these paths would shadow
    // package-manager-provided libraries and break linkage.
    if host == target {
        return;
    }

    match target.as_str() {
        "aarch64-unknown-linux-gnu" => {
            println!("cargo:rustc-link-search=native=/usr/lib/aarch64-linux-gnu");
            println!("cargo:rustc-link-lib=elf");
            println!("cargo:rustc-link-lib=z");
        }
        "armv7-unknown-linux-gnueabihf" => {
            println!("cargo:rustc-link-search=native=/usr/lib/arm-linux-gnueabihf");
            println!("cargo:rustc-link-lib=elf");
            println!("cargo:rustc-link-lib=z");
        }
        "x86_64-unknown-freebsd" => {
            // FreeBSD uses libpcap from base system (in /usr/lib)
            // When cross-compiling, the sysroot should provide these
            println!("cargo:rustc-link-lib=pcap");
        }
        _ => {
            // For other targets, including native builds, let pkg-config handle it
        }
    }
}

fn generate_assets() -> Result<()> {
    use clap::ValueEnum;
    use clap_complete::Shell;
    use clap_mangen::Man;

    let mut cmd = build_cli();

    // build into `RUSTNET_ASSET_DIR` with a fallback to `OUT_DIR`
    let asset_dir: PathBuf = env::var_os("RUSTNET_ASSET_DIR")
        .or_else(|| env::var_os("OUT_DIR"))
        .ok_or_else(|| anyhow::anyhow!("OUT_DIR is unset"))?
        .into();

    // completion
    for &shell in Shell::value_variants() {
        clap_complete::generate_to(shell, &mut cmd, "rustnetec", &asset_dir)?;
    }

    // manpage
    let mut manpage_out = File::create(asset_dir.join("rustnetec.1"))?;
    let manpage = Man::new(cmd);
    manpage.render(&mut manpage_out)?;

    Ok(())
}

/// rustnetec: 构建期把 rustnetec.ico 嵌入 exe 资源，使 rustnetec.exe 在
/// 资源管理器/任务栏显示品牌图标。仅 Windows 原生构建生效（build.rs 的
/// cfg(target_os) 基于宿主平台；macOS 交叉编译不会执行）。
#[cfg(target_os = "windows")]
fn embed_windows_icon() -> Result<()> {
    let mut res = winres::WindowsResource::new();
    res.set_icon("resources/packaging/windows/graphics/rustnetec.ico");
    res.compile()
        .map_err(|e| anyhow::anyhow!("winres failed to embed rustnetec.ico: {e}"))?;
    println!("cargo:rerun-if-changed=resources/packaging/windows/graphics/rustnetec.ico");
    Ok(())
}

#[cfg(target_os = "windows")]
fn download_windows_npcap_sdk() -> Result<()> {
    use sha2::{Digest, Sha256};
    use std::{
        fs,
        io::{self, Write},
    };

    println!("cargo:rerun-if-changed=build.rs");

    // get npcap SDK
    const NPCAP_SDK: &str = "npcap-sdk-1.15.zip";
    const NPCAP_SDK_SHA256: &str =
        "52c7b9fb4abee3ad9fe739bb545c3efe77b731c8e127122bdf328eafdae3ed4f";

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let npcap_sdk_download_url = format!("https://npcap.com/dist/{NPCAP_SDK}");
    // rustnetec: vendor 路径（一级来源，完全离线）。GitHub Actions Windows runner
    // 访问 npcap.com 经常连接超时（os error 10060），因此把 SDK zip 提交到仓库，
    // 构建优先读本地，CI 不再依赖外网下载。
    let npcap_sdk_vendor_path = manifest_dir
        .join("resources/packaging/windows")
        .join(NPCAP_SDK);
    // target 缓存（二级来源，历史构建产物；与 CI actions/cache 的
    // target/${{ matrix.target }} 不同，这里在 target/ 根目录）。
    let cache_dir = manifest_dir.join("target");
    let npcap_sdk_cache_path = cache_dir.join(NPCAP_SDK);

    // 三级来源：vendor 路径 → target 缓存 → 在线下载（带重试）
    let npcap_zip = match fs::read(&npcap_sdk_vendor_path) {
        // use vendored copy (offline; verify checksum)
        Ok(zip_data) => {
            eprintln!(
                "Using vendored npcap SDK: {}",
                npcap_sdk_vendor_path.display()
            );
            verify_npcap_checksum(&zip_data)?;
            zip_data
        }
        Err(_) => match fs::read(&npcap_sdk_cache_path) {
            // use cached (verify checksum)
            Ok(zip_data) => {
                eprintln!("Found cached npcap SDK");
                verify_npcap_checksum(&zip_data)?;
                zip_data
            }
            // download SDK (fallback with retry)
            Err(_) => {
                eprintln!(
                    "npcap SDK not found in vendor path or target cache; downloading from npcap.com"
                );
                let mut zip_data = vec![];
                download_npcap_with_retry(&npcap_sdk_download_url, &mut zip_data)?;

                // verify checksum before caching
                verify_npcap_checksum(&zip_data)?;

                // write cache
                fs::create_dir_all(&cache_dir)?;
                let mut cache = fs::File::create(&npcap_sdk_cache_path)?;
                cache.write_all(&zip_data)?;

                zip_data
            }
        },
    };

    fn verify_npcap_checksum(data: &[u8]) -> Result<()> {
        let hash = Sha256::digest(data);
        let actual = hash.iter().map(|b| format!("{b:02x}")).collect::<String>();
        if actual != NPCAP_SDK_SHA256 {
            anyhow::bail!(
                "Npcap SDK checksum mismatch!\n  Expected: {}\n  Actual:   {}\n\
                 The downloaded file may be corrupted or tampered with.",
                NPCAP_SDK_SHA256,
                actual
            );
        }
        eprintln!("Npcap SDK checksum verified: {actual}");
        Ok(())
    }

    // extract libraries based on target architecture
    let target = env::var("TARGET").unwrap_or_else(|_| "unknown".to_string());
    let (packet_lib_path, wpcap_lib_path) = if target.contains("aarch64") {
        ("Lib/ARM64/Packet.lib", "Lib/ARM64/wpcap.lib")
    } else if target.contains("x86_64") {
        ("Lib/x64/Packet.lib", "Lib/x64/wpcap.lib")
    } else if target.contains("i686") || target.contains("i586") {
        ("Lib/Packet.lib", "Lib/wpcap.lib")
    } else {
        panic!("Unsupported target: {}", target)
    };

    let mut archive = zip::ZipArchive::new(io::Cursor::new(npcap_zip))?;

    // Extract Packet.lib
    let mut packet_lib = archive.by_name(packet_lib_path)?;
    let lib_dir = PathBuf::from(env::var("OUT_DIR")?).join("npcap_sdk");
    fs::create_dir_all(&lib_dir)?;
    let packet_lib_dest = lib_dir.join("Packet.lib");
    let mut packet_file = fs::File::create(packet_lib_dest)?;
    io::copy(&mut packet_lib, &mut packet_file)?;
    drop(packet_lib);

    // Extract wpcap.lib
    let mut wpcap_lib = archive.by_name(wpcap_lib_path)?;
    let wpcap_lib_dest = lib_dir.join("wpcap.lib");
    let mut wpcap_file = fs::File::create(wpcap_lib_dest)?;
    io::copy(&mut wpcap_lib, &mut wpcap_file)?;

    println!(
        "cargo:rustc-link-search=native={}",
        lib_dir
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("{lib_dir:?} is not valid UTF-8"))?
    );

    // rustnetec: 延迟加载 wpcap.dll / Packet.dll，使 Npcap 未安装时程序仍能
    // 正常启动（不再被 PE 加载器在 main() 之前拦截），随后由
    // check_windows_dependencies() 给出友好引导。仅 MSVC 链接器支持
    // /DELAYLOAD；GNU 目标（*-pc-windows-gnu）不支持该参数，跳过以维持现状。
    //
    // /DELAYLOAD 依赖 delay-load 辅助函数 __delayLoadHelper2，该符号由
    // delayimp.lib 提供，因此必须一并链接。
    if target.contains("msvc") {
        println!("cargo:rustc-link-lib=dylib=delayimp");
        println!("cargo:rustc-link-arg=/DELAYLOAD:wpcap.dll");
        println!("cargo:rustc-link-arg=/DELAYLOAD:Packet.dll");
    }

    Ok(())
}

/// rustnetec: 带重试的 npcap SDK 在线下载（兜底路径）。
///
/// GitHub Actions Windows runner 访问 npcap.com 常超时（os error 10060），
/// 单次请求失败率高；这里最多重试 3 次、间隔 2s。由于 vendor zip 已入库，
/// 正常情况下此函数不会被走到。
#[cfg(target_os = "windows")]
fn download_npcap_with_retry(url: &str, out: &mut Vec<u8>) -> Result<()> {
    const MAX_ATTEMPTS: u32 = 3;
    let mut last_err: Option<String> = None;
    for attempt in 1..=MAX_ATTEMPTS {
        out.clear();
        match http_req::request::get(url, out) {
            Ok(_) => {
                eprintln!("npcap SDK downloaded (attempt {attempt}/{MAX_ATTEMPTS})");
                return Ok(());
            }
            Err(e) => {
                eprintln!(
                    "npcap SDK download attempt {attempt}/{MAX_ATTEMPTS} failed: {e}"
                );
                last_err = Some(format!("{e}"));
                if attempt < MAX_ATTEMPTS {
                    std::thread::sleep(std::time::Duration::from_secs(2));
                }
            }
        }
    }
    anyhow::bail!(
        "npcap SDK download failed after {MAX_ATTEMPTS} attempts: {:?}",
        last_err
    )
}
