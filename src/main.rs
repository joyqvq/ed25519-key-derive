fn main() {
    println!("Hello, world!");
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use base58::ToBase58;
    use ed25519_dalek::Keypair;
    use key_derive::{ExtendedSecretKey, DerivationPath};

    use {
        bip39::{Language, Mnemonic, Seed},
    };
        
    fn keypair_from_seed_and_derivation_path(seed: &[u8], derivation_path: DerivationPath) -> Keypair {
        let extended = ExtendedSecretKey::from_seed(seed)
        .and_then(|extended| extended.derive(&derivation_path)).unwrap();
        let extended_public_key = extended.public_key();
        Keypair {
            secret: extended.secret_key,
            public: extended_public_key,
        }
    }

    #[test]
    fn test_keypair_from_seed_phrase_and_passphrase() {
        let mnemonic = Mnemonic::from_phrase("romance holiday episode nature tourist pen flock desk spoil silk clown anger", Language::English).unwrap();
        let passphrase = "";
        let seed = Seed::new(&mnemonic, passphrase);

        let keypair =
            keypair_from_seed_and_derivation_path(seed.as_bytes(), DerivationPath::from_str("m/44'/501'/0'/0'/0'").unwrap());
        let keypair2 =
            keypair_from_seed_and_derivation_path(seed.as_bytes(), DerivationPath::from_str("m/44'/501'/0'/0'").unwrap());
        let keypair3 =
            keypair_from_seed_and_derivation_path(seed.as_bytes(), DerivationPath::from_str("m/44'/501'/0'").unwrap());
        let keypair4 =
            keypair_from_seed_and_derivation_path(seed.as_bytes(), DerivationPath::from_str("m/44'/501'/0'/0/0").unwrap());
        println!("pubkey: {:?}", keypair.public.as_bytes().to_base58());
        println!("pubkey2: {:?}", keypair2.public.as_bytes().to_base58());
        println!("pubkey3: {:?}", keypair3.public.as_bytes().to_base58());
        println!("pubkey4: {:?}", keypair4.public.as_bytes().to_base58());
    }
}