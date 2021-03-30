use revault_tx::scripts::*;

use rand::RngCore;
use revault_tx::{
    bitcoin::{hashes::hex::ToHex, secp256k1, PublicKey},
    miniscript::{Descriptor, Miniscript, NullCtx, Segwitv0},
};

fn get_random_pubkey() -> PublicKey {
    let secp = secp256k1::Secp256k1::new();
    let mut rand_bytes = [0u8; 32];

    rand::thread_rng().fill_bytes(&mut rand_bytes);
    let secret_key = secp256k1::SecretKey::from_slice(&rand_bytes).expect("curve order");

    PublicKey {
        compressed: true,
        key: secp256k1::PublicKey::from_secret_key(&secp, &secret_key),
    }
}

fn get_miniscripts(
    n_participants: usize,
    n_man: usize,
) -> Result<
    (
        Miniscript<PublicKey, Segwitv0>,
        Miniscript<PublicKey, Segwitv0>,
    ),
    Box<dyn std::error::Error>,
> {
    let (mut non_man, mut man, mut cosigners) = (
        Vec::<PublicKey>::with_capacity(n_participants - n_man),
        Vec::<PublicKey>::with_capacity(n_man),
        Vec::<PublicKey>::with_capacity(n_participants - n_man),
    );

    for _ in 0..n_man {
        man.push(get_random_pubkey());
    }

    for _ in n_man..n_participants {
        non_man.push(get_random_pubkey());
        cosigners.push(get_random_pubkey());
    }

    let mut participants = Vec::<PublicKey>::new();
    participants.extend(&non_man);
    participants.extend(&man);

    Ok((
        match deposit_descriptor(participants)?.0 {
            Descriptor::Wsh(ms) => ms,
            _ => unreachable!(),
        },
        match unvault_descriptor(non_man, man, n_man, cosigners, 144)?.0 {
            Descriptor::Wsh(ms) => ms,
            _ => unreachable!(),
        },
    ))
}

// Display the Bitcoin Script and Miniscript policy of the vault and unvault txout
// scripts given the number of participants and the number of man of the vault.
// Both are P2WSH so we display the Witness Script, as the Witness Program is not interesting.
fn display_one(n_participants: usize, n_man: usize) -> Result<(), Box<dyn std::error::Error>> {
    let (vault_miniscript, unvault_miniscript) = get_miniscripts(n_participants, n_man).unwrap();
    let (vault_script, unvault_script) = (
        vault_miniscript.encode(NullCtx),
        unvault_miniscript.encode(NullCtx),
    );

    println!("vault output:");
    println!("-------------");
    println!("  Miniscript: {}", vault_miniscript);
    println!("  Witness Script: {}", vault_script);
    println!("  Raw Witness Script: {}", vault_script.to_hex());
    println!(
        "  Program size: {} WU",
        vault_miniscript.script_size(NullCtx)
    );
    println!(
        "  Witness size: {} WU",
        vault_miniscript.max_satisfaction_size().unwrap()
    );

    println!("\n======================\n");

    println!("unvault output:");
    println!("---------------");
    println!("  Miniscript: {}", unvault_miniscript);
    println!("  Witness Script: {}", unvault_script);
    println!("  Raw Witness Script: {}", unvault_script.to_hex());
    println!(
        "  Program size: {} WU",
        unvault_miniscript.script_size(NullCtx)
    );
    println!(
        "  Witness size: {} WU",
        unvault_miniscript.max_satisfaction_size().unwrap()
    );

    Ok(())
}

// This assumes all managers are stakeholders
//fn custom_unvault_descriptor(
//n_stakeholders: usize,
//n_managers: usize,
//) -> Result<Descriptor<PublicKey>, revault_tx::Error> {
//let managers_pks: Vec<PublicKey> = (0..n_managers).map(|_| get_random_pubkey()).collect();
//let stakeholders_pks: Vec<PublicKey> =
//(0..n_stakeholders).map(|_| get_random_pubkey()).collect();
//let cosigners_pks: Vec<PublicKey> = (0..n_stakeholders).map(|_| get_random_pubkey()).collect();

//raw_unvault_descriptor(
//stakeholders_pks,
//n_stakeholders,
//1,
//managers_pks,
//n_managers,
//cosigners_pks,
//n_stakeholders,
//32,
//10,
//)
//}

//fn display_all() {
//let mut n_stakeholders = 1;

//loop {
//let all_desc: Vec<(usize, Descriptor<PublicKey>)> = (1..n_stakeholders + 1)
//.filter_map(|n_managers| {
//custom_unvault_descriptor(n_stakeholders, n_managers)
//.ok()
//.and_then(|desc| Some((n_managers, desc)))
//})
//.collect();

//if all_desc.is_empty() {
//return;
//}

//for (n_managers, desc) in all_desc {
//println!(
//"{},{},{}",
//n_stakeholders,
//n_managers,
//desc.max_satisfaction_weight().unwrap()
//);
//}

//// For pm3d
//println!("\n");

//n_stakeholders += 1;
//}
//}

fn parse_args(args: &Vec<String>) -> bool {
    if args.len() < 2 || args[1].eq_ignore_ascii_case("help") {
        return false;
    }

    if args[1].eq_ignore_ascii_case("getone") {
        if args.len() < 4 {
            eprintln!("I need the number of participants and man !!\n");
            return false;
        }

        if let Ok(n_participants) = args[2].parse::<usize>() {
            if let Ok(n_man) = args[3].parse::<usize>() {
                if n_man >= n_participants || n_man < 1 {
                    eprintln!("Invalid number of participants and/or man..");
                    return false;
                }

                if let Err(e) = display_one(n_participants, n_man) {
                    eprintln!("Miniscript error: {}", e);
                }
            } else {
                eprintln!("The number of man must be a number..");
                return false;
            }
        } else {
            eprintln!("The number of participants must be a number..");
            return false;
        }
    } else if args[1].eq_ignore_ascii_case("getall") {
        eprintln!("Disabled"); // FIXME: fix display_all()
        return false;
        //display_all();
    }

    true
}

fn show_usage(args: &[String]) {
    println!("{} [help | getone | getall] (params)", args[0]);
    println!("  help: prints this message.");
    println!(
        "  getone [number of participants] [number of man]: get the vault \
        and unvault script and policy for this configuration."
    );
    println!(
        "  getall: get all possible unvault configurations and theirwitness' \
        weight as plots (n_part, n_man, WU)."
    );
}

fn main() {
    use std::{env, process};

    let args = env::args().collect();
    if !parse_args(&args) {
        show_usage(&args);
        process::exit(1);
    }
}
