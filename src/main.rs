use ethers_providers::{Middleware, Provider, Http};
use revm::{
    db::{DbAccount, EmptyDB, InMemoryDB},
    inspector_handle_register,
    inspectors::TracerEip3155,
    primitives::{AccountInfo, Address, TransactTo, U256, B256},
    DatabaseCommit, Evm, precompile::Bytes
};
use serde_json::Value;
use std::fs::{self, File};
use std::path::Path;
use std::{collections::HashMap, str::FromStr};
use tokio_postgres::NoTls;
use log::info;
use std::sync::Arc;
use ethers_core::types::BlockId;

pub mod utils;
pub mod configs;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // TODO: fetch blocks from sql database
    let config = configs::read_config();

    let database_params = format!(
        "host={} user={} password={} dbname={}",
        config.database.host,
        config.database.user,
        config.database.password,
        config.database.dbname
    );

    let (client, connection) =
    tokio_postgres::connect(&database_params, NoTls).await.unwrap();

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("connection error: {}", e);
        }
    });
        
    println!("Connected to database");

    // Only if we are starting from scratch
    let mut db = InMemoryDB::new(EmptyDB::new());
    let mut block_height: i32 = 0;

    let resume = Path::new("./data/states.json").exists();

    if resume {
        // Load states.json
        let states_string = fs::read_to_string("./data/states.json").unwrap();
        let states: serde_json::Value = serde_json::from_str(&states_string).unwrap();
        db = serde_json::from_value(states).unwrap();

        // get the height
        let height_string = fs::read_to_string("./data/height.txt").unwrap();
        block_height = i32::from_str_radix(&height_string, 10).unwrap();
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
        println!("Loading genesis account");

        let file = File::open("mainnet.json").unwrap();
        let genesis: serde_json::Value = serde_json::from_reader(file).unwrap();
        let alloc = genesis.get("alloc").unwrap();
        let allocs: HashMap<String, Value> = serde_json::from_value(alloc.clone()).unwrap();

        for (address, balance) in allocs.iter() {
            let address = Address::from_str(address).unwrap();
            let balance = balance.get("balance").unwrap().as_str().unwrap();
            let info = AccountInfo::from_balance(U256::from_str_radix(&balance[2..], 16).unwrap());
            evm.db_mut().insert_account_info(address, info);
        }

        // update block (do we need this one ?)
        evm = evm
            .modify()
            .modify_block_env(|block| {
                let number = genesis.get("number").unwrap().as_str().unwrap();
                let coinbase =
                    Address::from_str(genesis.get("coinbase").unwrap().as_str().unwrap()).unwrap();
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
            200_000_i32 => {
                evm = evm
                    .modify()
                    .with_spec_id(revm::primitives::SpecId::FRONTIER_THAWING)
                    .build();
            }
            1_150_000_i32 => {
                evm = evm
                    .modify()
                    .with_spec_id(revm::primitives::SpecId::HOMESTEAD)
                    .build();
            }
            1_920_000_i32 => {
                evm = evm
                    .modify()
                    .with_spec_id(revm::primitives::SpecId::DAO_FORK)
                    .build();
            }
            2_463_000_i32 => {
                evm = evm
                    .modify()
                    .with_spec_id(revm::primitives::SpecId::TANGERINE)
                    .build();
            }
            2_675_000_i32 => {
                evm = evm
                    .modify()
                    .with_spec_id(revm::primitives::SpecId::SPURIOUS_DRAGON)
                    .build();
            }
            4_370_000_i32 => {
                evm = evm
                    .modify()
                    .with_spec_id(revm::primitives::SpecId::BYZANTIUM)
                    .build();
            }
            7_280_000_i32 => {
                evm = evm
                    .modify()
                    .with_spec_id(revm::primitives::SpecId::CONSTANTINOPLE)
                    .build();
            } //overwritten with PETERSBURG
            7_280_000_i32 => {
                evm = evm
                    .modify()
                    .with_spec_id(revm::primitives::SpecId::PETERSBURG)
                    .build();
            }
            9_069_000_i32 => {
                evm = evm
                    .modify()
                    .with_spec_id(revm::primitives::SpecId::ISTANBUL)
                    .build();
            }
            9_200_000_i32 => {
                evm = evm
                    .modify()
                    .with_spec_id(revm::primitives::SpecId::MUIR_GLACIER)
                    .build();
            }
            // 11_052_984_i32 => { evm = evm.modify().with_spec_id(revm::primitives::SpecId::STAKING_DEPOSIT_CONTRACT_DEPLOYED).build(); },
            12_244_000_i32 => {
                evm = evm
                    .modify()
                    .with_spec_id(revm::primitives::SpecId::BERLIN)
                    .build();
            }
            12_965_000_i32 => {
                evm = evm
                    .modify()
                    .with_spec_id(revm::primitives::SpecId::LONDON)
                    .build();
            }
            13_773_000_i32 => {
                evm = evm
                    .modify()
                    .with_spec_id(revm::primitives::SpecId::ARROW_GLACIER)
                    .build();
            }
            15_050_000_i32 => {
                evm = evm
                    .modify()
                    .with_spec_id(revm::primitives::SpecId::GRAY_GLACIER)
                    .build();
            }
            15_537_394_i32 => {
                evm = evm
                    .modify()
                    .with_spec_id(revm::primitives::SpecId::MERGE)
                    .build();
            } // PARIS
            17_034_870_i32 => {
                evm = evm
                    .modify()
                    .with_spec_id(revm::primitives::SpecId::SHANGHAI)
                    .build();
            }
            19_426_587_i32 => {
                evm = evm
                    .modify()
                    .with_spec_id(revm::primitives::SpecId::CANCUN)
                    .build();
            }
            _ => {}
        }
        println!("Beginning queries for blocks");
        let block_row = client.query_one(
            "SELECT hash, number, coinbase, difficulty, gas_limit, time, state_root
            FROM ethereum_mainnet.blocks
            WHERE number = $1",
            &[&block_height]).await.unwrap();
        
        println!("Finished query");

        let block_hash: Vec<u8> = block_row.get("hash");
        println!("block_hash assigned");
        let number: i32 = block_row.get("number");
        println!("number assigned");
        let coinbase: Vec<u8> = block_row.get("coinbase");
        println!("coinbase assigned");
        let difficulty: i64 = block_row.get("difficulty");
        println!("difficulty assigned");
        let gas_limit: i32 = block_row.get("gas_limit");
        println!("gas_limit assigned");
        let time: i32 = block_row.get("time");
        println!("time assigned");
        let state_root: Vec<u8> = block_row.get("state_root");
        println!("state_root assigned");

        println!("Fetched block number: {}", number);

        evm = evm
            .modify()
            .modify_block_env(|b| {
                b.number = U256::try_from(number).unwrap();
                b.coinbase = Address::from_slice(&coinbase);
                b.timestamp = U256::try_from(time).unwrap();
                b.gas_limit = U256::try_from(gas_limit).unwrap();
                b.difficulty = U256::try_from(difficulty).unwrap();
            })
            .build();
        
        println!("EVM environment built");

        // IMPORTANT !!! insert block hash value in db because otherwise BLOCKHASH opcode will return the wrong value (see error block 62102)
        evm.db_mut().block_hashes.insert(U256::try_from(number).unwrap(), B256::from_slice(&block_hash));
        
        println!("Starting queries for transactions");

        let tx_rows = client.query(
            "SELECT fromaddress, gas_limit, gas_price, value, data, nonce, toaddress
           FROM ethereum_mainnet.transactions
           WHERE block = $1",
           &[&block_hash]).await.unwrap();

        for tx in tx_rows {
            // check caller
            let caller: Address = Address::from_slice(tx.get("fromaddress"));
            let account = evm.db_mut().load_account(caller).unwrap().clone();

            evm = evm
                .modify()
                .modify_tx_env(|etx| {
                    etx.caller = caller;
                    println!("caller assigned");
                    let gas_limit: i64 = tx.get("gas_limit");
                    etx.gas_limit = gas_limit as u64;
                    println!("gas limit assigned");
                    etx.gas_price = U256::from_le_slice(tx.get("gas_price"));
                    println!("gas price assigned");
                    etx.value = U256::from_le_slice(tx.get("value"));
                    println!("value assigned");
                    etx.data = Bytes::copy_from_slice(tx.get("data"));
                    println!("data assigned");
                    etx.nonce = None;
                    println!("nonce set to none");
                    let to_address: Vec<u8> = tx.get("toaddress");
                    println!("to_address assigned");
                    etx.transact_to = match to_address.is_empty() {
                        true => {
                            TransactTo::Call(Address::from_slice(&to_address))
                        }
                        false => TransactTo::Create,
                    };
                })
                .build();

            // Construct the file writer to write the trace to
            let evm_result = evm.transact();

            if let Ok(r) = evm_result {
                let revm::primitives::ResultAndState { result, state } = r;

                dbg!(&result);
                // dbg!(&state);

                if result.is_success() {
                    evm.db_mut().commit(state);
                    println!("Transaction sent");
                } else {
                    println!("Transaction halted at block {}", number);
                    evm.db_mut().commit(state);
                }

                // TODO: Check for CREATE2 opcode execution here
            } else {
                println!("Transaction failed at block {}", number);
                dbg!(&evm_result);
                dbg!(&account);
                // This shouldn't happen
                evm_result.unwrap();
            }
        }

        // fetching uncles and calculate reward

        // calculate the block reward and give it to the coinbase address
        let coinbase_author = Address::from_slice(&coinbase);
        let block_reward = U256::from_str_radix("5000000000000000000", 10).unwrap(); // 5 ETH (Frontier block reward)

        let mut coinbase_author_account = evm
            .db()
            .accounts
            .get(&coinbase_author)
            .unwrap_or(&DbAccount::default())
            .clone();

        // let mut coinbase_author_account = evm.db_mut().load_account(coinbase_author).unwrap().clone();

        let http_client = Provider::<Http>::try_from(
            "http://167.235.37.100:8545",
        )?;
        let http_client = Arc::new(http_client);

        let uncle_count = match http_client.get_uncle_count(BlockId::from(block_height as u64)).await {
            Ok(count) => count.as_u64(),
            Err(error) => anyhow::bail!("Error: {:?}", error),
        };

        // uncle inclusion reward is block reward / 32
        let uncles_inlusion_reward =
            block_reward / U256::from_str_radix("32", 10).unwrap() * U256::from(uncle_count);
        coinbase_author_account.info.balance =
            coinbase_author_account.info.balance + block_reward + uncles_inlusion_reward;

        evm.db_mut()
            .insert_account_info(coinbase_author, coinbase_author_account.info);

        for uncle_index in 0..uncle_count {
            let uncle = match http_client.get_uncle(BlockId::from(block_height as u64), uncle_index.into()).await {
                Ok(Some(uncle)) => uncle,
                Ok(None) => anyhow::bail!("Block uncle not found"),
                Err(error) => anyhow::bail!("Error: {:?}", error),
            };

            let mut uncle_reward =
                U256::from_str(&(uncle.number.unwrap() + 8 - number).to_string())
                    .unwrap();
            uncle_reward = uncle_reward * block_reward;
            uncle_reward = uncle_reward.div_ceil(U256::from_le_slice(&8_u8.to_le_bytes()));

            let coinbase_author = Address::from(uncle.author.unwrap().as_fixed_bytes());

            let mut coinbase_author_account = evm
                .db()
                .accounts
                .get(&coinbase_author)
                .unwrap_or(&DbAccount::default())
                .clone();

            // let mut coinbase_author_account = evm.db_mut().load_account(coinbase_author).unwrap().clone();
            coinbase_author_account.info.balance =
                coinbase_author_account.info.balance + uncle_reward;

            evm.db_mut()
                .insert_account_info(coinbase_author, coinbase_author_account.info);
        }

        block_height = block_height + 1;

        if block_height % 1000 == 0 {
            let accounts = &evm.db().accounts;
            let calc_state_root = utils::calculate_state_root(accounts.clone());

            dbg!((
                hex::encode(&calc_state_root),
                hex::encode(&state_root)
            ));
            assert_eq!(calc_state_root, state_root);

            println!("Save at block, {}", block_height);
            utils::save_state(evm.db(), block_height as u64);
        }
    }

    utils::save_state(evm.db(), block_height as u64);

    Ok(())
}
