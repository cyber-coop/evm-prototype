use revm::{
    db::{DbAccount, EmptyDB, InMemoryDB}, inspector_handle_register, inspectors::TracerEip3155, primitives::{AccountInfo, Address, TransactTo, B256, U256}, Database, DatabaseCommit, Evm
};
use ethers_providers::Middleware;
use ethers_providers::{Http, Provider};
use std::{collections::HashMap, str::FromStr, sync::Arc};
use std::fs::{self, File};
use serde_json::Value;
use std::path::Path;

pub mod utils;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // TODO: fetch blocks from sql database
    let client = Provider::<Http>::try_from(
        "http://167.235.37.100:8545",
    )?;
    let client = Arc::new(client);

    // Only if we are starting from scratch
    let mut db = InMemoryDB::new(EmptyDB::new());
    let mut block_height = 0;


    let resume = Path::new("./data/states.json").exists();
    
    if resume {
        // Load states.json
        let states_string = fs::read_to_string("./data/states.json").unwrap();
        let states: serde_json::Value = serde_json::from_str(&states_string).unwrap();
        db = serde_json::from_value(states).unwrap();

        // get the height
        let height_string = fs::read_to_string("./data/height.txt").unwrap();
        block_height = u64::from_str_radix(&height_string, 10).unwrap();
    };

    // Using empty because we don't need this info for now
    let tracer = TracerEip3155::new(Box::new(std::io::empty()));
    // let tracer = TracerEip3155::new(Box::new(std::io::stdout()));

    let mut evm = Evm::builder()
                    .with_db(db)
                    .with_external_context(tracer)
                    .append_handler_register(inspector_handle_register)
                    .with_spec_id(revm::primitives::SpecId::FRONTIER)
                    .modify_cfg_env(|c| {
                        c.chain_id = 1;
                    })
                    .build();

    if !resume {
        // we need to load the mainnet genesis account to get the right state
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

        // update block (do we need this one ?)
        evm = evm.modify().modify_block_env(|block| {
            let number = genesis.get("number").unwrap().as_str().unwrap();
            let coinbase = Address::from_str(genesis.get("coinbase").unwrap().as_str().unwrap()).unwrap();
            let timestamp = genesis.get("timestamp").unwrap().as_str().unwrap();
            let gas_limit = genesis.get("gasLimit").unwrap().as_str().unwrap();
            let difficulty = genesis.get("difficulty").unwrap().as_str().unwrap();

            block.number = U256::from_str_radix(&number[2..], 16).unwrap();
            block.coinbase = coinbase;
            block.timestamp = U256::from_str_radix(&timestamp[2..], 16).unwrap();
            block.gas_limit = U256::from_str_radix(&gas_limit[2..], 16).unwrap();
            block.difficulty = U256::from_str_radix(&difficulty[2..], 16).unwrap();
        })
        .build();

        block_height = 1;
    }


    while block_height < 1500000 {

        // Update SPEC_ID based
        match block_height {
            200_000_u64 => { evm = evm.modify().with_spec_id(revm::primitives::SpecId::FRONTIER_THAWING).build(); },
            1_150_000_u64 => { evm = evm.modify().with_spec_id(revm::primitives::SpecId::HOMESTEAD).build(); },
            1_920_000_u64 => { evm = evm.modify().with_spec_id(revm::primitives::SpecId::DAO_FORK).build(); },
            2_463_000_u64 => { evm = evm.modify().with_spec_id(revm::primitives::SpecId::TANGERINE).build(); },
            2_675_000_u64 => { evm = evm.modify().with_spec_id(revm::primitives::SpecId::SPURIOUS_DRAGON).build(); },
            4_370_000_u64 => { evm = evm.modify().with_spec_id(revm::primitives::SpecId::BYZANTIUM).build(); },
            7_280_000_u64 => { evm = evm.modify().with_spec_id(revm::primitives::SpecId::CONSTANTINOPLE).build(); }, //overwritten with PETERSBURG
            7_280_000_u64 => { evm = evm.modify().with_spec_id(revm::primitives::SpecId::PETERSBURG).build(); },
            9_069_000_u64 => { evm = evm.modify().with_spec_id(revm::primitives::SpecId::ISTANBUL).build(); },
            9_200_000_u64 => { evm = evm.modify().with_spec_id(revm::primitives::SpecId::MUIR_GLACIER).build(); },
            // 11_052_984_u64 => { evm = evm.modify().with_spec_id(revm::primitives::SpecId::STAKING_DEPOSIT_CONTRACT_DEPLOYED).build(); },
            12_244_000_u64 => { evm = evm.modify().with_spec_id(revm::primitives::SpecId::BERLIN).build(); },
            12_965_000_u64 => { evm = evm.modify().with_spec_id(revm::primitives::SpecId::LONDON).build(); },
            13_773_000_u64 => { evm = evm.modify().with_spec_id(revm::primitives::SpecId::ARROW_GLACIER).build(); },
            15_050_000_u64 => { evm = evm.modify().with_spec_id(revm::primitives::SpecId::GRAY_GLACIER).build(); },
            15_537_394_u64 => { evm = evm.modify().with_spec_id(revm::primitives::SpecId::MERGE).build(); }, // PARIS
            17_034_870_u64 => { evm = evm.modify().with_spec_id(revm::primitives::SpecId::SHANGHAI).build(); },
            19_426_587_u64 => { evm = evm.modify().with_spec_id(revm::primitives::SpecId::CANCUN).build(); },
            _ => {},
        }


        let block = match client.get_block_with_txs(block_height).await {
            Ok(Some(block)) => block,
            Ok(None) => anyhow::bail!("Block not found"),
            Err(error) => anyhow::bail!("Error: {:?}", error),
        };
        println!("Fetched block number: {}", block.number.unwrap().0[0]);
    
        evm = evm.modify().modify_block_env(|b| {
            if let Some(number) = block.number {
                let nn = number.0[0];
                b.number = U256::from(nn);
            }

            if let Some(author) = block.author {
                b.coinbase = Address::from(author.as_fixed_bytes());
            }

            b.timestamp = U256::from_limbs(block.timestamp.0);
            b.gas_limit = U256::from_limbs(block.gas_limit.0);
            b.difficulty = U256::from_limbs(block.difficulty.0);

        })
        .build();

        // IMPORTANT !!! insert block hash value in db because otherwise BLOCKHASH opcode will return the wrong value (see error block 62102)
        evm.db_mut().block_hashes.insert(U256::from(block.number.unwrap().0[0]), B256::from_slice(block.hash.unwrap().as_bytes()));

        for tx in block.transactions {
            // check caller
            let caller = Address::from(tx.from.as_fixed_bytes());
            let account = evm.db_mut().load_account(caller).unwrap().clone();

            evm = evm
                .modify()
                .modify_tx_env(|etx| {
                    etx.caller = Address::from(tx.from.as_fixed_bytes());                  
                    etx.gas_limit = tx.gas.as_u64();
                    etx.gas_price = U256::from_limbs(tx.gas_price.unwrap().0);
                    etx.value = U256::from_limbs(tx.value.0);
                    etx.data = tx.input.0.into();
                    etx.nonce = Some(tx.nonce.as_u64());
                    etx.transact_to = match tx.to {
                        Some(to_address) => {
                            TransactTo::Call(Address::from(to_address.as_fixed_bytes()))
                        }
                        None => TransactTo::Create,
                    };
                })
                .build();
    
            // Construct the file writer to write the trace to
            let _tx_number = tx.transaction_index.unwrap().0[0];
            // dbg!(tx_number);

            let evm_result = evm.transact();

            if let Ok(r) = evm_result {
                let revm::primitives::ResultAndState { result, state } = r;

                // dbg!(&result);
                // dbg!(&state);

                if result.is_success() {
                    evm.db_mut().commit(state);
                } else {
                    println!("Transaction halted at block {}", block.number.unwrap().0[0]);
                    evm.db_mut().commit(state);
                }

                // TODO: Check for CREATE2 opcode execution here

            } else {
                println!("Transaction failed at block {}", block.number.unwrap().0[0]);
                dbg!(&evm_result);
                dbg!(&account);
                // This shouldn't happen
                evm_result.unwrap();
            }

        }

        // fetching uncles and calculate reward
        
        // calculate the block reward and give it to the coinbase address
        let coinbase_author = Address::from(block.author.unwrap().as_fixed_bytes());
        let block_reward = U256::from_str_radix("5000000000000000000", 10).unwrap(); // 5 ETH (Frontier block reward)

        let mut coinbase_author_account = evm.db().accounts.get(&coinbase_author).unwrap_or(&DbAccount::default()).clone();

        // let mut coinbase_author_account = evm.db_mut().load_account(coinbase_author).unwrap().clone();

        let uncle_count = match client.get_uncle_count(block_height).await {
            Ok(count) => { count.as_u64() },
            Err(error) => anyhow::bail!("Error: {:?}", error),
        };

        // uncle inclusion reward is block reward / 32
        let uncles_inlusion_reward = block_reward / U256::from_str_radix("32", 10).unwrap() * U256::from(uncle_count);
        coinbase_author_account.info.balance = coinbase_author_account.info.balance + block_reward + uncles_inlusion_reward;

        evm.db_mut().insert_account_info(coinbase_author, coinbase_author_account.info);

        for uncle_index in 0..uncle_count {
            let uncle = match client.get_uncle(block_height, uncle_index.into()).await {
                Ok(Some(uncle)) => uncle,
                Ok(None) => anyhow::bail!("Block uncle not found"),
                Err(error) => anyhow::bail!("Error: {:?}", error),
            };

            let mut uncle_reward = U256::from_str(&(uncle.number.unwrap() + 8 - block.number.unwrap()).to_string()).unwrap();
            uncle_reward = uncle_reward * block_reward;
            uncle_reward = uncle_reward.div_ceil(U256::from_le_slice(&8_u8.to_le_bytes()));

            let coinbase_author = Address::from(uncle.author.unwrap().as_fixed_bytes());

            let mut coinbase_author_account = evm.db().accounts.get(&coinbase_author).unwrap_or(&DbAccount::default()).clone();

            // let mut coinbase_author_account = evm.db_mut().load_account(coinbase_author).unwrap().clone();
            coinbase_author_account.info.balance = coinbase_author_account.info.balance + uncle_reward;

            evm.db_mut().insert_account_info(coinbase_author, coinbase_author_account.info);
        }

        block_height = block_height + 1;

        if block_height % 1000 == 0 {
            let accounts = &evm.db().accounts;
            let state_root = utils::calculate_state_root(accounts.clone());
    
            dbg!((hex::encode(&state_root), hex::encode(&block.state_root.as_bytes())));
            assert_eq!(state_root, block.state_root.as_bytes());

            println!("Save at block, {}", block_height);
            utils::save_state(evm.db(), block_height);
        }
    }

    utils::save_state(evm.db(), block_height);

    Ok(())
}