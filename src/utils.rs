use std::io::Write;
use std::str::FromStr;
use revm::InMemoryDB;
use revm::db::PlainAccount;
use revm::primitives::{keccak256, Address, B256, U256};
use triehash::sec_trie_root;
use hash_db::Hasher;
use plain_hasher::PlainHasher;
use revm::db::DbAccount;
use rlp::RlpStream;
use std::sync::Arc;
use eth_trie::MemoryDB;
use eth_trie::{EthTrie, Trie};
use revm::db::AccountState;

pub fn save_state(db: &InMemoryDB, block_heigh: u64) {
    let states = serde_json::to_string(db).unwrap();
    let mut states_file = std::fs::OpenOptions::new().write(true).truncate(true).create(true).open("./data/states.json").unwrap();
    states_file.write_all(states.as_bytes()).unwrap();
    states_file.flush().unwrap();

    let mut height_file = std::fs::OpenOptions::new().write(true).truncate(true).create(true).open("./data/height.txt").unwrap();
    height_file.write_all(block_heigh.to_string().as_bytes()).unwrap();
    height_file.flush().unwrap();
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeccakHasher;

impl Hasher for KeccakHasher {
    type Out = B256;
    type StdHasher = PlainHasher;
    const LENGTH: usize = 32;

    #[inline]
    fn hash(x: &[u8]) -> Self::Out {
        keccak256(x)
    }
}

struct TrieAccount {
    nonce: u64,
    balance: Vec<u8>, // It actually is a big number
    root_hash: Vec<u8>,
    code_hash: Vec<u8>,
}

impl TrieAccount {
    fn new(acc: &PlainAccount) -> Self {
        let root_hash = sec_trie_root::<KeccakHasher, _, _, _>(
            acc.storage
                .iter()
                .filter(|(_k, &v)| v != U256::ZERO)
                .map(|(k, v)| (k.to_be_bytes::<32>(), alloy_rlp::encode_fixed_size(v))),
        );

        Self {
            nonce: acc.info.nonce,
            balance: acc.info.balance.as_le_slice().to_vec(),
            root_hash: root_hash.to_vec(),
            code_hash: acc.info.code_hash.to_vec(),
        }
    }
}

pub fn calculate_state_root(accounts: impl IntoIterator<Item = (Address, DbAccount)>,) -> Vec<u8> {
    let memdb = Arc::new(MemoryDB::new(true));
    let mut state_trie = EthTrie::new(memdb.clone());

    for account in accounts.into_iter() {
        if account.1.account_state == AccountState::NotExisting {
            continue;
        } 

        let memdb = Arc::new(MemoryDB::new(true));
        let mut storage_trie = EthTrie::new(memdb.clone());

        for (k, v) in account.1.storage.into_iter() {
            if v == U256::ZERO {
                continue;
            }

            let mut k = k.as_le_slice().to_vec();
            // we need  to reverse because we want big endian and not little endian
            k.reverse();
            let mut tmp: Vec<u8> = vec![];
            tmp.resize(32 - k.len(), 0);
            tmp.append(&mut k);
            // Because it is secure hash trie we hash the key before doing the insert (storage trie)
            let hash_key = keccak256(tmp).to_vec();

            storage_trie.insert(&hash_key, &alloy_rlp::encode_fixed_size(&v)).unwrap();
        }

        let mut stream = RlpStream::new_list(4);
        stream.append(&account.1.info.nonce);
        // We need to reverse !!!
        let mut balance = account.1.info.balance.as_le_bytes_trimmed().to_vec();
        balance.reverse();
        stream.append(&balance.to_vec());
        stream.append(&storage_trie.root_hash().unwrap().as_bytes());
        stream.append(&account.1.info.code_hash.to_vec());

        // Because it is secure hash trie we hash the key before doing the insert (state trie)
        let address_hash = keccak256(account.0.as_slice()).to_vec();

        state_trie.insert(&address_hash, stream.as_raw()).unwrap();
    };

    return state_trie.root_hash().unwrap().as_bytes().to_vec();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::HashMap, str::FromStr};
    use std::fs::File;
    use serde_json::Value;
    use revm::primitives::{AccountInfo, U256};
    use revm::db::EmptyDB;
    use revm::Evm;  
    use std::sync::Arc;
    use eth_trie::MemoryDB;
    use eth_trie::{EthTrie, Trie};
    use std::collections::BTreeMap;

    #[test]
    fn test_state_root() {
        let db = InMemoryDB::new(EmptyDB::new());
        let mut evm = Evm::builder()
            .with_db(db)
            .with_spec_id(revm::primitives::SpecId::FRONTIER)
            .modify_cfg_env(|c| {
                c.chain_id = 1;
            })
            .build();


        let file = File::open("mainnet.json").unwrap();
        let genesis: serde_json::Value = serde_json::from_reader(file).unwrap();
        let alloc = genesis.get("alloc").unwrap();
        let allocs : HashMap<String, Value> = serde_json::from_value(alloc.clone()).unwrap();

        for (address, balance) in allocs.iter() {
            let address = Address::from_str(address).unwrap();
            let balance = balance.get("balance").unwrap().as_str().unwrap();
            let info = AccountInfo::from_balance(U256::from_str_radix(&balance[2..], 16).unwrap());
            evm.db_mut().insert_account_info(address, info);
        }

        let accounts = &evm.db().accounts;
        let state_root = calculate_state_root(accounts.clone());

        assert_eq!(hex::encode(state_root), "d7f8974fb5ac78d9ac099b9ad5018bedc2ce0a72dad1827a1709da30580f0544");

    }

    #[test]
    fn basic_test_root() {
        let test = BTreeMap::from([
            ("do", "verb"),
            ("ether", "wookiedoo"),
            ("horse", "stallion"),
            ("shaman", "horse"),
            ("doge", "coin"),
            ("ether", ""),
            ("dog", "puppy"),
            ("shaman", "")
        ]);

        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = EthTrie::new(memdb.clone());
        
        for (k, v) in test.into_iter() {
            trie.insert(k.as_bytes(), v.as_bytes()).unwrap();
        }

        assert_eq!(hex::encode(trie.root_hash().unwrap().as_bytes()), "5991bb8c6514148a29db676a14ac506cd2cd5775ace63c30a4fe457715e9ac84");
    }

    #[test]
    fn test_basic_state_root() {
        let test = BTreeMap::from([
            ("a94f5374fce5edbc8e2a8697c15331677e6ebf0b",
            "f84c01880de0b6b3a7622746a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"),
            ("095e7baea6a6c7c4c2dfeb977efac326af552d87", 
            "f84780830186b7a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0501653f02840675b1aab0328c6634762af5d51764e78f9641cccd9b27b90db4f"),
            ("2adc25665018aa1fe0e6bc666dac8fc2697ff9ba", 
            "f8468082521aa056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"),
        ]);

        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = EthTrie::new(memdb.clone());
        
        for (k, v) in test.into_iter() {
            let address_hash = keccak256(hex::decode(&k).unwrap()).to_vec();
            trie.insert(&address_hash, &hex::decode(v).unwrap()).unwrap();
        }

        assert_eq!(hex::encode(trie.root_hash().unwrap().as_bytes()), "a7c787bf470808896308c215e22c7a580a0087bb6db6e8695fb4759537283a83");
    }

    #[test]
    fn test_basic_state_root_2() {
        let test = BTreeMap::from([
            ("a94f5374fce5edbc8e2a8697c15331677e6ebf0b",
            "f84c01880de0b6b3a7622746a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"),
            ("095e7baea6a6c7c4c2dfeb977efac326af552d87", 
            "f84780830186b7a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0501653f02840675b1aab0328c6634762af5d51764e78f9641cccd9b27b90db4f"),
            ("2adc25665018aa1fe0e6bc666dac8fc2697ff9ba", 
            "f8468082521aa056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"),
        ]);

        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = EthTrie::new(memdb.clone());
        
        for (k, v) in test.into_iter() {
            let address_hash = keccak256(hex::decode(&k).unwrap()).to_vec();

            let data = hex::decode(&v).unwrap();

            let s = rlp::Rlp::new(&data);

            // dbg!(hex::encode(s.at(0).unwrap().as_val::<Vec<u8>>().unwrap()));
            // dbg!(hex::encode(s.at(1).unwrap().as_val::<Vec<u8>>().unwrap()));
            // dbg!(hex::encode(s.at(2).unwrap().as_val::<Vec<u8>>().unwrap()));
            // dbg!(hex::encode(s.at(3).unwrap().as_val::<Vec<u8>>().unwrap()));

            let nonce: u64 = s.at(0).unwrap().as_val().unwrap();
            let balance: Vec<u8> = s.at(1).unwrap().as_val().unwrap();
            let storage_root: Vec<u8> = s.at(2).unwrap().as_val().unwrap();
            let code_hash: Vec<u8> = s.at(3).unwrap().as_val().unwrap();



            let mut stream = RlpStream::new_list(4);
            stream.append(&nonce);
            stream.append(&balance);
            stream.append(&storage_root);
            stream.append(&code_hash);

            dbg!(hex::encode(&stream.as_raw()));


            trie.insert(&address_hash, &stream.as_raw()).unwrap();
        }

        assert_eq!(hex::encode(trie.root_hash().unwrap().as_bytes()), "a7c787bf470808896308c215e22c7a580a0087bb6db6e8695fb4759537283a83");
    }

    #[test]
    fn test_storage_root() {
        // holesky storage contract tests
        let mut test = BTreeMap::from([
            ("22", "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b"),
            ("0000000000000000000000000000000000000000000000000000000000000023", "db56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d71"),
            ("0000000000000000000000000000000000000000000000000000000000000024", "c78009fdf07fc56a11f122370658a353aaa542ed63e44c4bc15ff4cd105ab33c"),
            ("0000000000000000000000000000000000000000000000000000000000000025", "536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c"),
            ("0000000000000000000000000000000000000000000000000000000000000026", "9efde052aa15429fae05bad4d0b1d7c64da64d03d7a1854a588c2cb8430c0d30"),
            ("0000000000000000000000000000000000000000000000000000000000000027", "d88ddfeed400a8755596b21942c1497e114c302e6118290f91e6772976041fa1"),
            ("0000000000000000000000000000000000000000000000000000000000000028", "87eb0ddba57e35f6d286673802a4af5975e22506c7cf4c64bb6be5ee11527f2c"),
            ("0000000000000000000000000000000000000000000000000000000000000029", "26846476fd5fc54a5d43385167c95144f2643f533cc85bb9d16b782f8d7db193"),
            ("000000000000000000000000000000000000000000000000000000000000002a", "506d86582d252405b840018792cad2bf1259f1ef5aa5f887e13cb2f0094f51e1"),
            ("000000000000000000000000000000000000000000000000000000000000002b", "ffff0ad7e659772f9534c195c815efc4014ef1e1daed4404c06385d11192e92b"),
            ("000000000000000000000000000000000000000000000000000000000000002c", "6cf04127db05441cd833107a52be852868890e4317e6a02ab47683aa75964220"),
            ("000000000000000000000000000000000000000000000000000000000000002d", "b7d05f875f140027ef5118a2247bbb84ce8f2f0f1123623085daf7960c329f5f"),
            ("000000000000000000000000000000000000000000000000000000000000002e", "df6af5f5bbdb6be9ef8aa618e4bf8073960867171e29676f8b284dea6a08a85e"),
            ("000000000000000000000000000000000000000000000000000000000000002f", "b58d900f5e182e3c50ef74969ea16c7726c549757cc23523c369587da7293784"),
            ("0000000000000000000000000000000000000000000000000000000000000030", "d49a7502ffcfb0340b1d7885688500ca308161a7f96b62df9d083b71fcc8f2bb"),
            ("0000000000000000000000000000000000000000000000000000000000000031", "8fe6b1689256c0d385f42f5bbe2027a22c1996e110ba97c171d3e5948de92beb"),
            ("0000000000000000000000000000000000000000000000000000000000000032", "8d0d63c39ebade8509e0ae3c9c3876fb5fa112be18f905ecacfecb92057603ab"),
            ("0000000000000000000000000000000000000000000000000000000000000033", "95eec8b2e541cad4e91de38385f2e046619f54496c2382cb6cacd5b98c26f5a4"),
            ("0000000000000000000000000000000000000000000000000000000000000034", "f893e908917775b62bff23294dbbe3a1cd8e6cc1c35b4801887b646a6f81f17f"),
            ("0000000000000000000000000000000000000000000000000000000000000035", "cddba7b592e3133393c16194fac7431abf2f5485ed711db282183c819e08ebaa"),
            ("0000000000000000000000000000000000000000000000000000000000000036", "8a8d7fe3af8caa085a7639a832001457dfb9128a8061142ad0335629ff23ff9c"),
            ("0000000000000000000000000000000000000000000000000000000000000037", "feb3c337d7a51a6fbf00b9e34c52e1c9195c969bd4e7a0bfd51d5c5bed9c1167"),
            ("0000000000000000000000000000000000000000000000000000000000000038", "e71f0aa83cc32edfbefa9f4d3e0174ca85182eec9f3a09f6a6c0df6377a510d7"),
            ("0000000000000000000000000000000000000000000000000000000000000039", "31206fa80a50bb6abe29085058f16212212a60eec8f049fecb92d8c8e0a84bc0"),
            ("000000000000000000000000000000000000000000000000000000000000003a", "21352bfecbeddde993839f614c3dac0a3ee37543f9b412b16199dc158e23b544"),
            ("000000000000000000000000000000000000000000000000000000000000003b", "619e312724bb6d7c3153ed9de791d764a366b389af13c58bf8a8d90481a46765"),
            ("000000000000000000000000000000000000000000000000000000000000003c", "7cdd2986268250628d0c10e385c58c6191e6fbe05191bcc04f133f2cea72c1c4"),
            ("000000000000000000000000000000000000000000000000000000000000003d", "848930bd7ba8cac54661072113fb278869e07bb8587f91392933374d017bcbe1"),
            ("000000000000000000000000000000000000000000000000000000000000003e", "8869ff2c22b28cc10510d9853292803328be4fb0e80495e8bb8d271f5b889636"),
            ("000000000000000000000000000000000000000000000000000000000000003f", "b5fe28e79f1b850f8658246ce9b6a1e7b49fc06db7143e8fe0b4f2b0c5523a5c"),
            ("0000000000000000000000000000000000000000000000000000000000000040", "985e929f70af28d0bdd1a90a808f977f597c7c778c489e98d3bd8910d31ac0f7"),
        ]);


        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = EthTrie::new(memdb.clone());
        
        for (k, v) in test.into_iter() {
            let mut k = hex::decode(k).unwrap();
            let mut tmp: Vec<u8> = vec![];
            tmp.resize(32 - k.len(), 0);
            tmp.append(&mut k);
            dbg!(hex::encode(&tmp));
            let key_hash = keccak256(&tmp).to_vec();

            let mut stream = RlpStream::new();
            stream.append(&hex::decode(&v).unwrap());

            dbg!(hex::encode(&stream.as_raw()));

            trie.insert(&key_hash, &stream.as_raw()).unwrap();
        }

        dbg!(hex::encode(trie.root_hash().unwrap().as_bytes()));

    }
}