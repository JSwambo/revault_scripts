use revault_tx::{scripts::*, transactions::*, txins::*, txouts::*};
use std::str::FromStr;

use rand::RngCore;
use revault_tx::{
    bitcoin::{hashes::hex::ToHex, secp256k1, util::bip32, Address, Network, OutPoint, PublicKey},
    miniscript::{
        descriptor::DescriptorSinglePub, Descriptor, DescriptorPublicKey, DescriptorPublicKeyCtx,
        Miniscript, NullCtx, Segwitv0,
    },
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

struct Participants {
    pub stakeholders: Vec<DescriptorPublicKey>,
    pub cosigners: Vec<DescriptorPublicKey>,
    pub managers: Vec<DescriptorPublicKey>,
}

impl Participants {
    pub fn new(n_stk: usize, n_man: usize) -> Self {
        // define participants set
        let mut stakeholders: Vec<DescriptorPublicKey> = Vec::new();
        let mut cosigners: Vec<DescriptorPublicKey> = Vec::new();
        for _stk in 0..n_stk {
            stakeholders.push(DescriptorPublicKey::SinglePub(DescriptorSinglePub {
                origin: None,
                key: get_random_pubkey(),
            }));
            cosigners.push(DescriptorPublicKey::SinglePub(DescriptorSinglePub {
                origin: None,
                key: get_random_pubkey(),
            }));
        }
        let mut managers: Vec<DescriptorPublicKey> = Vec::new();
        for _man in 0..n_man {
            managers.push(DescriptorPublicKey::SinglePub(DescriptorSinglePub {
                origin: None,
                key: get_random_pubkey(),
            }));
        }
        Self {
            stakeholders,
            cosigners,
            managers,
        }
    }
}

fn cancel_max_weight(
    n_stk: usize,
    n_man: usize,
    csv: u32,
    secp: &secp256k1::Secp256k1<secp256k1::All>,
) -> Result<usize, Box<dyn std::error::Error>> {
    let participants = Participants::new(n_stk, n_man);
    let child_number = bip32::ChildNumber::from(0);
    let xpub_ctx = DescriptorPublicKeyCtx::new(&secp, child_number);

    // Deposit and descriptors
    let deposit_descriptor = deposit_descriptor(participants.stakeholders.clone())
        .expect("Deposit descriptor generation error");
    let deposit_txo = DepositTxOut::new(100000000, &deposit_descriptor, xpub_ctx);
    let deposit_txin = DepositTxIn::new(
        OutPoint::from_str("39a8212c6a9b467680d43e47b61b8363fe1febb761f9f548eb4a432b2bc9bbec:0")
            .unwrap(),
        deposit_txo.clone(),
    );
    let unvault_descriptor = unvault_descriptor(
        participants.stakeholders,
        participants.managers.clone(),
        n_man,
        participants.cosigners,
        csv,
    )
    .expect("Unvault descriptor generation error");
    let cpfp_descriptor =
        cpfp_descriptor(participants.managers).expect("Unvault CPFP descriptor generation error");

    // Unvault transaction
    let unvault_tx = UnvaultTransaction::new(
        deposit_txin.clone(),
        &unvault_descriptor,
        &cpfp_descriptor,
        xpub_ctx,
        csv,
    )?;
    let unvault_txin = unvault_tx.revault_unvault_txin(&unvault_descriptor, xpub_ctx);
    let satisfied_input_weight = unvault_txin.max_sat_weight();

    // Cancel transaction
    let cancel =
        CancelTransaction::new(unvault_txin.clone(), None, &deposit_descriptor, xpub_ctx, 0);
    let mut cancel_tx = cancel.into_psbt().extract_tx();

    // Strip input
    cancel_tx.input = Vec::new();

    Ok(cancel_tx.get_weight() + satisfied_input_weight)
}

fn unvault_emergency_max_weight(
    n_stk: usize,
    n_man: usize,
    csv: u32,
    secp: &secp256k1::Secp256k1<secp256k1::All>,
) -> Result<usize, Box<dyn std::error::Error>> {
    let participants = Participants::new(n_stk, n_man);
    let child_number = bip32::ChildNumber::from(0);
    let xpub_ctx = DescriptorPublicKeyCtx::new(&secp, child_number);

    // Deposit and descriptors
    let deposit_descriptor = deposit_descriptor(participants.stakeholders.clone())
        .expect("Deposit descriptor generation error");
    let deposit_txo = DepositTxOut::new(100000000, &deposit_descriptor, xpub_ctx);
    let deposit_txin = DepositTxIn::new(
        OutPoint::from_str("39a8212c6a9b467680d43e47b61b8363fe1febb761f9f548eb4a432b2bc9bbec:0")
            .unwrap(),
        deposit_txo.clone(),
    );
    let unvault_descriptor = unvault_descriptor(
        participants.stakeholders,
        participants.managers.clone(),
        n_man,
        participants.cosigners,
        csv,
    )
    .expect("Unvault descriptor generation error");
    let cpfp_descriptor =
        cpfp_descriptor(participants.managers).expect("Unvault CPFP descriptor generation error");

    // Unvault transaction
    let unvault_tx = UnvaultTransaction::new(
        deposit_txin.clone(),
        &unvault_descriptor,
        &cpfp_descriptor,
        xpub_ctx,
        csv,
    )?;
    let unvault_txin = unvault_tx.revault_unvault_txin(&unvault_descriptor, xpub_ctx);
    let satisfied_input_weight = unvault_txin.max_sat_weight();

    // We reuse the deposit descriptor for the emergency address
    let emergency_address = EmergencyAddress::from(Address::p2wsh(
        &deposit_descriptor.0.witness_script(xpub_ctx),
        Network::Bitcoin,
    ))
    .expect("Emergency address generation error");

    // Unvault Emergency Tx
    let unemergency =
        UnvaultEmergencyTransaction::new(unvault_txin.clone(), None, emergency_address.clone(), 0);
    let mut unemergency_tx = unemergency.into_psbt().extract_tx();
    unemergency_tx.input = Vec::new();

    Ok(unemergency_tx.get_weight() + satisfied_input_weight)
}

fn emergency_max_weight(
    n_stk: usize,
    n_man: usize,
    secp: &secp256k1::Secp256k1<secp256k1::All>,
) -> Result<usize, Box<dyn std::error::Error>> {
    let participants = Participants::new(n_stk, n_man);
    let child_number = bip32::ChildNumber::from(0);
    let xpub_ctx = DescriptorPublicKeyCtx::new(&secp, child_number);

    // Deposit and descriptors
    let deposit_descriptor = deposit_descriptor(participants.stakeholders.clone())
        .expect("Deposit descriptor generation error");
    let deposit_txo = DepositTxOut::new(100000000, &deposit_descriptor, xpub_ctx);
    let deposit_txin = DepositTxIn::new(
        OutPoint::from_str("39a8212c6a9b467680d43e47b61b8363fe1febb761f9f548eb4a432b2bc9bbec:0")
            .unwrap(),
        deposit_txo.clone(),
    );

    let satisfied_input_weight = deposit_txin.max_sat_weight();

    // We reuse the deposit descriptor for the emergency address
    let emergency_address = EmergencyAddress::from(Address::p2wsh(
        &deposit_descriptor.0.witness_script(xpub_ctx),
        Network::Bitcoin,
    ))
    .expect("Emergency address generation error");

    // Unvault Emergency Tx
    let emergency =
        EmergencyTransaction::new(deposit_txin.clone(), None, emergency_address.clone(), 0)?;
    let mut emergency_tx = emergency.into_psbt().extract_tx();
    emergency_tx.input = Vec::new();

    Ok(emergency_tx.get_weight() + satisfied_input_weight)
}

fn feebump_satisfied_input_weight() -> usize {
    // P2WPKH address
    272
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
    } else if args[1].eq_ignore_ascii_case("maxweight_cancel") {
        if args.len() < 5 {
            eprintln!("I need the number of staleholders, managers and the CSV\n");
            return false;
        }

        if let Ok(n_stk) = args[2].parse::<usize>() {
            if let Ok(n_man) = args[3].parse::<usize>() {
                if n_stk < 1 || n_man < 1 {
                    eprintln!("Invalid number of stakeholders or managers..");
                    return false;
                }
                if let Ok(csv) = args[4].parse::<u32>() {
                    let secp = secp256k1::Secp256k1::new();
                    println!("{:?}", cancel_max_weight(n_stk, n_man, csv, &secp));
                }
            }
        }
    } else if args[1].eq_ignore_ascii_case("maxweight_unemergency") {
        if args.len() < 5 {
            eprintln!("I need the number of staleholders, managers and the CSV\n");
            return false;
        }

        if let Ok(n_stk) = args[2].parse::<usize>() {
            if let Ok(n_man) = args[3].parse::<usize>() {
                if n_stk < 1 || n_man < 1 {
                    eprintln!("Invalid number of stakeholders or managers..");
                    return false;
                }
                if let Ok(csv) = args[4].parse::<u32>() {
                    let secp = secp256k1::Secp256k1::new();
                    println!(
                        "{:?}",
                        unvault_emergency_max_weight(n_stk, n_man, csv, &secp)
                    );
                }
            }
        }
    } else if args[1].eq_ignore_ascii_case("maxweight_emergency") {
        if args.len() < 4 {
            eprintln!("I need the number of staleholders and managers\n");
            return false;
        }

        if let Ok(n_stk) = args[2].parse::<usize>() {
            if let Ok(n_man) = args[3].parse::<usize>() {
                if n_stk < 1 || n_man < 1 {
                    eprintln!("Invalid number of stakeholders or managers..");
                    return false;
                }
                let secp = secp256k1::Secp256k1::new();
                println!("{:?}", emergency_max_weight(n_stk, n_man, &secp));
            }
        }
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
