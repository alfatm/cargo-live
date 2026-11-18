mod hostkey;
mod job;
mod log;
mod mirror;
mod runner;
mod server;
mod session;
mod settings;
mod tokens;

use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;

use settings::{Cli, Command, TokenCommand};
use tokens::TokenFile;

pub type Result<T, E = Box<dyn std::error::Error + Send + Sync>> = std::result::Result<T, E>;

fn main() -> ExitCode {
    let mut args = std::env::args_os();
    let _ = args.next();
    let rest: Vec<_> = args.collect();
    if rest.first().is_some_and(|a| a == "__runner") {
        return ExitCode::from(runner::main(rest[1..].to_vec()) as u8);
    }
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("cargo-live-agent: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Serve(args) => {
            let settings = settings::settings(&args)?;
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?
                .block_on(serve(settings))
        }
        Command::Fingerprint(common) => {
            let paths = settings::paths(&common)?;
            let (key, generated) = hostkey::load_or_generate(&paths.host_key)?;
            if generated {
                eprintln!("generated host key {}", paths.host_key.display());
            }
            println!("{}", hostkey::fingerprint(&key)?);
            Ok(())
        }
        Command::Token(TokenCommand::Create { name, common }) => {
            let paths = settings::paths(&common)?;
            let mut file = TokenFile::load(&paths.tokens_file)?;
            let token = file.create(&name, log::now_rfc3339())?;
            file.save(&paths.tokens_file)?;
            eprintln!("created token {name:?}; it is shown only once:");
            println!("{token}");
            Ok(())
        }
        Command::Token(TokenCommand::List(common)) => {
            let paths = settings::paths(&common)?;
            let file = TokenFile::load(&paths.tokens_file)?;
            if file.tokens.is_empty() {
                eprintln!("no tokens in {}", paths.tokens_file.display());
            }
            for token in &file.tokens {
                println!("{}\t{}", token.name, token.created);
            }
            Ok(())
        }
        Command::Token(TokenCommand::Revoke { name, common }) => {
            let paths = settings::paths(&common)?;
            let mut file = TokenFile::load(&paths.tokens_file)?;
            file.revoke(&name)?;
            file.save(&paths.tokens_file)?;
            eprintln!("revoked token {name:?}");
            Ok(())
        }
    }
}

async fn serve(settings: settings::Settings) -> Result<()> {
    std::fs::create_dir_all(&settings.paths.data_dir)?;
    let (key, generated) = hostkey::load_or_generate(&settings.paths.host_key)?;
    if generated {
        log!("generated host key {}", settings.paths.host_key.display());
    }
    log!("host key fingerprint: {}", hostkey::fingerprint(&key)?);
    let tokens = TokenFile::load(&settings.paths.tokens_file)?;
    if tokens.tokens.is_empty() {
        log!(
            "warning: no tokens in {}; create one with `cargo-live-agent token create --name NAME`",
            settings.paths.tokens_file.display()
        );
    }
    let agent_exe = std::env::current_exe()?;
    let listener = tokio::net::TcpListener::bind(settings.listen)
        .await
        .map_err(|e| format!("cannot listen on {}: {e}", settings.listen))?;
    log!(
        "cargo-live-agent {} listening on {} (data dir {}, max {} concurrent builds, max {} connections)",
        env!("CARGO_PKG_VERSION"),
        listener.local_addr()?,
        settings.paths.data_dir.display(),
        settings.max_concurrent_builds,
        settings.max_connections
    );
    let config = server::ssh_config(key);
    let shared = Arc::new(server::Shared::new(settings, agent_exe));
    server::serve(shared, config, listener).await
}
