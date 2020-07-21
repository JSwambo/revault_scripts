use bitcoin::PublicKey;
use miniscript::policy::concrete::Policy;
use rand::RngCore;

// The vault policy is an N-of-N, so thresh(len(pubkeys), pubkeys)
fn vault_policy(participants: Vec<PublicKey>) -> Policy<PublicKey> {
    let pubkeys = participants
        .iter()
        .map(|pubkey| Policy::Key(*pubkey))
        .collect::<Vec<Policy<PublicKey>>>();

    Policy::Threshold(pubkeys.len(), pubkeys)
}

// The unvault policy is a bit more involved.  It allows either all the participants to spend, or
// all the spenders + cosigners + a timelock.
// As the spenders are part of the participants we can have a more efficient Script by expliciting
// to the compiler that the spenders are always going to sign.
// Thus we end up with:
// and(thresh(len(spenders), spenders), or(thresh(len(non_spenders), non_spenders),
// and(thresh(len(cosigners), cosigners), older(X))))
// As we expect the usual operations to be far more likely, we further optimize the policy to:
// and(thresh(len(spenders), spenders), or(1@thresh(len(non_spenders), non_spenders),
// 9@and(thresh(len(cosigners), cosigners), older(X))))
fn unvault_policy(
    non_spenders: Vec<PublicKey>,
    spenders: Vec<PublicKey>,
    cosigners: Vec<PublicKey>,
) -> Policy<PublicKey> {
    let mut pubkeys = spenders
        .iter()
        .map(|pubkey| Policy::Key(*pubkey))
        .collect::<Vec<Policy<PublicKey>>>();
    let spenders_thres = Policy::Threshold(pubkeys.len(), pubkeys);

    pubkeys = non_spenders
        .iter()
        .map(|pubkey| Policy::Key(*pubkey))
        .collect::<Vec<Policy<PublicKey>>>();
    let non_spenders_thres = Policy::Threshold(pubkeys.len(), pubkeys);

    pubkeys = cosigners
        .iter()
        .map(|pubkey| Policy::Key(*pubkey))
        .collect::<Vec<Policy<PublicKey>>>();
    let cosigners_thres = Policy::Threshold(pubkeys.len(), pubkeys);

    // FIXME CSV value
    let cosigners_and_csv = Policy::And(vec![cosigners_thres, Policy::Older(100)]);

    let cosigners_or_non_spenders =
        Policy::Or(vec![(9, cosigners_and_csv), (1, non_spenders_thres)]);

    Policy::And(vec![spenders_thres, cosigners_or_non_spenders])
}

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

fn get_policies(
    n_participants: usize,
    n_spenders: usize,
) -> (Policy<PublicKey>, Policy<PublicKey>) {
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

    (
        vault_policy(participants),
        unvault_policy(non_spenders, spenders, cosigners),
    )
}

// Display the Bitcoin Script and Miniscript policy of the vault and unvault txout
// scripts given the number of participants and the number of spenders of the vault.
fn display_one(n_participants: usize, n_spenders: usize) -> Result<(), Box<dyn std::error::Error>> {
    let (vault_policy, unvault_policy) = get_policies(n_participants, n_spenders);
    let vault_script = vault_policy.compile::<miniscript::Segwitv0>()?;
    let unvault_script = unvault_policy.compile::<miniscript::Segwitv0>()?;

    println!("vault output:");
    println!("-------------");
    println!("  Witness Program: {}", vault_script.encode());
    println!("  Program size: {} WU", vault_script.script_size());
    println!(
        "  Witness size: {} WU",
        vault_script.max_satisfaction_size(2)
    );

    println!("\n======================\n");

    println!("unvault output:");
    println!("---------------");
    println!("  Witness Program: {}", unvault_script.encode());
    println!("  Program size: {} WU", unvault_script.script_size());
    println!(
        "  Witness size: {} WU",
        unvault_script.max_satisfaction_size(2)
    );

    Ok(())
}

fn all_spenders_err(n_participants: usize, n_spenders: &mut usize) -> bool {
    for i in *n_spenders..n_participants {
        let (_, unvault_policy) = get_policies(n_participants, i);
        if let Ok(_) = unvault_policy.compile::<miniscript::Segwitv0>() {
            *n_spenders = i;
            return false;
        }
    }

    true
}

fn display_all() {
    let (mut n_participants, mut n_spenders) = (2, 1);

    loop {
        loop {
            // FIXME: get only the unvault policy
            let (_, unvault_policy) = get_policies(n_participants, n_spenders);

            if let Ok(unvault_script) = unvault_policy.compile::<miniscript::Segwitv0>() {
                println!(
                    "{},{},{}",
                    n_participants,
                    n_spenders,
                    unvault_script.max_satisfaction_size(2)
                );
                n_spenders += 1;
                continue;
            }

            break;
        }

        // For pm3d
        println!("\n");

        n_participants += 1;
        n_spenders = n_participants - n_spenders;

        let (_, unvault_policy) = get_policies(n_participants, n_spenders);
        // Hmm, we cannot find a standard Script with a minimal amount of spenders..
        if let Err(_) = unvault_policy.compile::<miniscript::Segwitv0>() {
            // .. But is there really no possible one ?
            if all_spenders_err(n_participants, &mut n_spenders) {
                break;
            }
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
