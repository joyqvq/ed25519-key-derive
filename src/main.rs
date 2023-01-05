fn main() {
    println!("Hello, world!");
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use base58::ToBase58;
    use ed25519_dalek::Keypair;
    use key_derive::{DerivationPath, ExtendedSecretKey};

    use bip39::{Language, Mnemonic, Seed};

    fn keypair_from_seed_and_derivation_path(
        seed: &[u8],
        derivation_path: DerivationPath,
    ) -> Keypair {
        let extended = ExtendedSecretKey::from_seed(seed)
            .and_then(|extended| extended.derive(&derivation_path))
            .unwrap();
        let extended_public_key = extended.public_key();
        Keypair {
            secret: extended.secret_key,
            public: extended_public_key,
        }
    }

    #[test]
    fn test_keypair_from_seed_phrase_and_passphrase() {
        let mnemonic = Mnemonic::from_phrase(
            "romance holiday episode nature tourist pen flock desk spoil silk clown anger",
            Language::English,
        )
        .unwrap();
        let passphrase = "";
        let seed = Seed::new(&mnemonic, passphrase);

        let paths = vec![
            "m/44'/501'/0'/0'/0'",
            "m/44'/501'/1'/0'/0'",
            "m/44'/501'/0'/0'",
            "m/44'/501'/0'",
            "m/44'/501'/1'",
            "m/44'/501'/0'/0/0",
            "m/44'/501'/0'/0",
            "m/44'/501'/0/0'",
            "m/44'/501'/0/0/0",
            "m/44'/501'/0/0",
            "m/44'/501'/0",
        ];
        println!("| path | pubkey |");
        println!("| ---- | ------ |");
        for path in paths {
            let keypair = keypair_from_seed_and_derivation_path(
                seed.as_bytes(),
                DerivationPath::from_str(path).unwrap(),
            );
            println!(
                "| {:?} | {:?} |",
                path,
                keypair.public.as_bytes().to_base58()
            );
        }
    }
}
