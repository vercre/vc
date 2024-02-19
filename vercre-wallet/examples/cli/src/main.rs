#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

mod core;
mod http;

use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use crossbeam_channel::unbounded;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;
use vercre_core::vci::CredentialOffer;
use vercre_wallet::issuance::{Effect, Event};

#[derive(Parser, Clone)]
enum Command {
    // Pin,
    AcceptOffer,
    // Get,
    // Inc,
    // Dec,
    // Watch,
}

impl From<Command> for Event {
    fn from(cmd: Command) -> Self {
        match cmd {
            // Command::Pin => Event::Pin("1234".to_string()),
            Command::AcceptOffer => Event::Accept,
            // Command::Get => Event::Get,
            // Command::Inc => Event::Increment,
            // Command::Dec => Event::Decrement,
            // Command::Watch => Event::StartWatch,
        }
    }
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    cmd: Command,
}

fn main() -> Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,surf=warn".into());
    let format = tracing_subscriber::fmt::layer();
    tracing_subscriber::registry().with(filter).with(format).init();

    let command = Args::parse().cmd;

    let core = core::new();
    let event = command.into();
    let (tx, rx) = unbounded::<Effect>();

    core::update(&core, event, &Arc::new(tx))?;

    while let Ok(effect) = rx.recv() {
        if let Effect::Render(_) = effect {
            let view = core.view();

            // let pin_required = view
            //     .offer
            //     .grants
            //     .as_ref()
            //     .unwrap()
            //     .pre_authorized_code
            //     .as_ref()
            //     .unwrap()
            //     .tx_code
            //     .unwrap();

            // if pin_required {
            println!("{view:?}");
            // }
        }
    }

    Ok(())
}
