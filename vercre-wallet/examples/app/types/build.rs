//! Generate UI-specific types used by each user interface to communicate with the
//! `vercre-wallet` core.

use vercre_wallet::typegen::{self, Language};

fn main() {
    typegen::generate(Language::Typescript, "./gen");
}
