use revault_tx::scripts::*;

use bitcoin::{secp256k1, PublicKey};
use miniscript::{Descriptor, Miniscript, Segwitv0};
use rand::RngCore;

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
    n_spenders: usize,
) -> Result<
    (
        Miniscript<PublicKey, Segwitv0>,
        Miniscript<PublicKey, Segwitv0>,
    ),
    Box<dyn std::error::Error>,
> {
    let (mut non_spenders, mut spenders, mut cosigners) = (
        Vec::<PublicKey>::new(),
        Vec::<PublicKey>::new(),
        Vec::<PublicKey>::new(),
    );

    for _ in 0..n_spenders {
        spenders.push(get_random_pubkey());
    }

    for _ in n_spenders..n_participants {
        non_spenders.push(get_random_pubkey());
        cosigners.push(get_random_pubkey());
    }

    let mut participants = Vec::<PublicKey>::new();
    participants.extend(&non_spenders);
    participants.extend(&spenders);

    Ok((
        match vault_descriptor(participants)?.0 {
            Descriptor::Wsh(ms) => ms,
            _ => unreachable!(),
        },
        match unvault_descriptor(non_spenders, spenders, cosigners, 144)?.0 {
            Descriptor::Wsh(ms) => ms,
            _ => unreachable!(),
        },
    ))
}

// Display the Bitcoin Script and Miniscript policy of the vault and unvault txout
// scripts given the number of participants and the number of spenders of the vault.
fn display_one(n_participants: usize, n_spenders: usize) -> Result<(), Box<dyn std::error::Error>> {
    let (vault_script, unvault_script) = get_miniscripts(n_participants, n_spenders).unwrap();

    println!("vault output:");
    println!("-------------");
    println!("  Miniscript: {}", vault_script);
    println!("  Witness Program: {}", vault_script.encode());
    println!("  Program size: {} WU", vault_script.script_size());
    println!(
        "  Witness size: {} WU",
        vault_script.max_satisfaction_size(2)
    );

    println!("\n======================\n");

    println!("unvault output:");
    println!("---------------");
    println!("  Miniscript: {}", unvault_script);
    println!("  Witness Program: {}", unvault_script.encode());
    println!("  Program size: {} WU", unvault_script.script_size());
    println!(
        "  Witness size: {} WU",
        unvault_script.max_satisfaction_size(2)
    );

    Ok(())
}

fn find_next_n_spenders(n_participants: usize, n_spenders: usize) -> Option<usize> {
    for i in n_spenders..n_participants {
        if get_miniscripts(n_participants, i).is_ok() {
            return Some(i);
        }
    }

    None
}

fn display_all() {
    let (mut n_participants, mut n_spenders) = (2, 1);

    loop {
        loop {
            // FIXME: get only the unvault policy
            if let Ok((_, unvault_ms)) = get_miniscripts(n_participants, n_spenders) {
                println!(
                    "{},{},{}",
                    n_participants,
                    n_spenders,
                    unvault_ms.max_satisfaction_size(2)
                );
                n_spenders += 1;
                continue;
            }

            break;
        }

        // For pm3d
        println!("\n");

        n_participants += 1;
        if let Some(found) = find_next_n_spenders(n_participants, n_participants - n_spenders) {
            n_spenders = found;
        } else {
            break;
        }
    }
}

fn parse_args(args: &Vec<String>) -> bool {
    if args.len() < 2 || args[1].eq_ignore_ascii_case("help") {
        return false;
    }

    if args[1].eq_ignore_ascii_case("getone") {
        if args.len() < 4 {
            eprintln!("I need the number of participants and spenders !!\n");
            return false;
        }

        if let Ok(n_participants) = args[2].parse::<usize>() {
            if let Ok(n_spenders) = args[3].parse::<usize>() {
                // FIXME: Allow n_spenders == n_participants (need to change cosigner logic)
                if n_spenders >= n_participants || n_spenders < 1 {
                    eprintln!("Invalid number of participants and/or spenders..");
                    return false;
                }

                if let Err(e) = display_one(n_participants, n_spenders) {
                    eprintln!("Miniscript error: {}", e);
                }
            } else {
                eprintln!("The number of spenders must be a number..");
                return false;
            }
        } else {
            eprintln!("The number of participants must be a number..");
            return false;
        }
    } else if args[1].eq_ignore_ascii_case("getall") {
        display_all();
    }

    true
}

fn show_usage(args: &[String]) {
    println!("{} [help | getone | getall] (params)", args[0]);
    println!("  help: prints this message.");
    println!(
        "  getone [number of participants] [number of spenders]: get the vault \
        and unvault script and policy for this configuration."
    );
    println!(
        "  getall: get all possible unvault configurations and theirwitness' \
        weight as plots (n_part, n_spenders, WU)."
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
