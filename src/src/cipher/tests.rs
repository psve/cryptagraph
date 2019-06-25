/* Macroes to help ease testing of Cipher implementations
 */
macro_rules! test_linear_layer {
    ($impl:path) => {
        #[allow(unused_imports)]
        use proptest::prelude::*;

        #[test]
        fn test_linear_layer() {
            let cipher = <$impl>::new();
            let config = ProptestConfig {
                timeout : 1000,
                verbose : 2,
                max_shrink_time : 1000,
                .. ProptestConfig::default()
            };

            proptest!(config, |(x : u128)| {
                let x = x & ((1 << cipher.size()) - 1);
                let y = cipher.linear_layer(x);
                assert!(y < (1 << cipher.size()));
                assert_eq!(x, cipher.linear_layer_inv(y));
            })
        }
    }
}

macro_rules! test_encryption_decryption {
    ($impl:path) => {
        #[allow(unused_imports)]
        use proptest::prelude::*;

        #[test]
        fn test_encryption_decryption() {
            let cipher = <$impl>::new();
            let config = ProptestConfig {
                timeout : 1000,
                verbose : 2,
                max_shrink_time : 1000,
                .. ProptestConfig::default()
            };

            proptest!(config, |(pt : u128, keys : Vec<u128>)| {
                let msk : u128 = (1 << cipher.size()) - 1;
                let keys : Vec<u128> = keys.into_iter().map(|x| x & msk).collect();
                let pt = pt & msk;
                let ct = cipher.encrypt(pt, &keys);
                println!("0x{:x} -enc({:?})-> 0x{:x}", pt, keys, ct);
                let ppt = cipher.decrypt(ct, &keys);
                assert_eq!(ppt, pt);
            })
        }
    }
}

/// Generic property-based testsuite for cipher implementation
macro_rules! cipher_test_suite {
    ($impl:path) => {
        test_linear_layer!($impl);
        test_encryption_decryption!($impl);
    }
}

macro_rules! cipher_testvector_encryption {
    ($impl:path, $tests:expr) => {
    }
}
