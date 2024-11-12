use clap::Parser;
use fuel_asm::RawInstruction;
use fuel_debugger::names::register_name;
use fuel_types::Bytes32;
use shellfish::command::CommandType;
use shellfish::{async_fn, AsyncHandler};
use shellfish::{Command as ShCommand, Shell};
use surf::utils::async_trait;
use std::collections::HashMap;
use std::error::Error;
use std::sync::Arc;
use tokio::sync::Mutex;
use shellfish::command::Command;
use fuel_debugger::{names, ContractId, FuelClient, RunResult, Transaction};
use fuel_vm::consts::{VM_MAX_RAM, VM_REGISTER_COUNT, WORD_SIZE};
use yansi::Paint;

#[derive(Parser, Debug)]
pub struct Opt {
    #[clap(default_value = "http://127.0.0.1:4000/graphql")]
    pub api_url: String,
}


/// Shellfish's async handler with last-command repetition functionality
#[derive(Clone)]
pub struct RepeatLastCommandHandler {
    last_command: Arc<Mutex<Option<Vec<String>>>>,
}

impl RepeatLastCommandHandler {
    pub fn new() -> Self {
        Self {
            last_command: Arc::new(Mutex::new(None)),
        }
    }
}

#[async_trait]
impl<T: Send> AsyncHandler<T> for RepeatLastCommandHandler {
    async fn handle_async(
        &self,
        mut line: Vec<String>,
        commands: &HashMap<&str, Command<T>>,
        state: &mut T,
        description: &str,
    ) -> bool {
        // Use the last command if `line` is empty
        if line.is_empty() {
            let last_command = self.last_command.lock().await;
            if let Some(last_cmd) = &*last_command {
                println!("Repeating last command: {}", last_cmd.join(" "));
                line = last_cmd.clone();
            } else {
                println!("No previous command to repeat.");
                return false;
            }
        } else {
            // Update the last command
            *self.last_command.lock().await = Some(line.clone());
        }

        if let Some(command) = line.get(0) {
            // Add some padding
            println!();

            match command.as_str() {
                "quit" | "exit" => return true,
                "help" => {
                    println!("{}", description);
                    // Print information about built-in commands
                    println!("    help - displays help information.");
                    println!("    quit - quits the shell.");
                    println!("    exit - exits the shell.");
                    for (name, command) in commands {
                        println!("    {} - {}", name, command.help);
                    }
                }
                _ => {
                    // Attempt to find the command
                    let command = commands.get(&line[0] as &str);

                    // Check if we got it
                    match command {
                        Some(command) => {
                            if let Err(e) = match command.command {
                                CommandType::Sync(c) => c(state, line),
                                CommandType::Async(a) => a(state, line).await,
                            } {
                                eprintln!(
                                    "{}",
                                    format!(
                                        "Command exited unsuccessfully:\n{}\n({:?})",
                                        &e, &e
                                    )
                                );
                            }
                        }
                        None => {
                            eprintln!("{} {}", Paint::red("Command not found:"), line[0]);
                        }
                    }
                }
            }

            // Padding
            println!();
        }
        false
    }
}


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Opt::parse();

    // Initialize the last command as an empty string wrapped in an Arc<Mutex<>>
    let handler = RepeatLastCommandHandler::new();

    let mut shell = Shell::new_with_async_handler(
        State {
            client: FuelClient::new(&config.api_url)?,
            session_id: String::new(), // Placeholder
        },
        ">> ",
        handler
    );

    macro_rules! command {
        ($f:ident, $help:literal, $names:expr) => {
            for c in $names {
                shell.commands.insert(
                    c,
                    ShCommand::new_async($help.to_string(), async_fn!(State, $f)),
                );
            }
        };
    }

    command!(
        cmd_start_tx,
        "path/to/tx.json -- start a new tx",
        ["n", "tx", "new_tx", "start_tx"]
    );
    command!(
        cmd_reset,
        "-- reset, removing breakpoints and other state",
        ["reset", "clear"]
    );
    command!(
        cmd_continue,
        "-- run until next breakpoint or termination",
        ["c", "continue"]
    );
    command!(
        cmd_step,
        "[on|off] -- turn single-stepping on or off",
        ["s", "step"]
    );
    command!(
        cmd_breakpoint,
        "[contract_id] offset -- set a breakpoint",
        ["b", "breakpoint"]
    );
    command!(
        cmd_registers,
        "[regname ...] -- dump registers",
        ["r", "reg", "register", "registers"]
    );
    command!(cmd_memory, "[offset] limit -- dump memory", ["m", "memory", "mem"]);
    command!(cmd_code, "[offset] limit -- dump code", ["d", "disass", "code"]);
    //get current call frame : [frame, fr (fr)]
    command!(cmd_frame, "[offset] limit -- dump code", ["fr", "frame"]);
    command!(
        cmd_search_memory,
        "[start] [end] pattern -- search memory",
        ["search"]
    );

    let session_id = shell.state.client.start_session().await?;
    shell.state.session_id = session_id.clone();
    shell.run_async().await?;
    shell.state.client.end_session(&session_id).await?;
    Ok(())
}

struct State {
    client: FuelClient,
    session_id: String,
}

#[derive(Debug, thiserror::Error)]
enum ArgError {
    #[error("Invalid argument")]
    Invalid,
    #[error("Not enough arguments")]
    NotEnough,
    #[error("Too many arguments")]
    TooMany,
}

fn pretty_print_run_result(rr: &RunResult) {
    for receipt in rr.receipts() {
        println!("Receipt: {:?}", receipt);
    }
    if let Some(bp) = &rr.breakpoint {
        println!(
            "Stopped on breakpoint at address {} of contract {}",
            bp.pc.0, bp.contract
        );
    } else {
        println!("Terminated");
    }
}

async fn cmd_start_tx(state: &mut State, mut args: Vec<String>) -> Result<(), Box<dyn Error>> {
    args.remove(0);
    let path_to_tx_json = args.pop().ok_or_else(|| Box::new(ArgError::NotEnough))?;
    if !args.is_empty() {
        return Err(Box::new(ArgError::TooMany));
    }

    let tx_json = std::fs::read(path_to_tx_json)?;
    let tx: Transaction = serde_json::from_slice(&tx_json).unwrap();
    let status = state.client.start_tx(&state.session_id, &tx).await?;
    pretty_print_run_result(&status);

    Ok(())
}

async fn cmd_reset(state: &mut State, mut args: Vec<String>) -> Result<(), Box<dyn Error>> {
    args.remove(0);
    if !args.is_empty() {
        return Err(Box::new(ArgError::TooMany));
    }

    let _ = state.client.reset(&state.session_id).await?;

    Ok(())
}

async fn cmd_continue(state: &mut State, mut args: Vec<String>) -> Result<(), Box<dyn Error>> {
    args.remove(0);
    if !args.is_empty() {
        return Err(Box::new(ArgError::TooMany));
    }

    let status = state.client.continue_tx(&state.session_id).await?;
    pretty_print_run_result(&status);

    cmd_code(state, vec!["code".to_string()]).await?;

    Ok(())
}

async fn cmd_step(state: &mut State, mut args: Vec<String>) -> Result<(), Box<dyn Error>> {
    args.remove(0);
    if args.len() > 1 {
        return Err(Box::new(ArgError::TooMany));
    }

    state
        .client
        .set_single_stepping(
            &state.session_id,
            args.first()
                .map(|v| !["off", "no", "disable"].contains(&v.as_str()))
                .unwrap_or(true),
        )
        .await?;
    Ok(())
}

async fn cmd_breakpoint(state: &mut State, mut args: Vec<String>) -> Result<(), Box<dyn Error>> {
    args.remove(0);
    let offset = args.pop().ok_or_else(|| Box::new(ArgError::NotEnough))?;
    let contract_id = args.pop();

    if !args.is_empty() {
        return Err(Box::new(ArgError::TooMany));
    }

    let offset = if let Some(offset) = parse_int(&offset) {
        offset as u64
    } else {
        return Err(Box::new(ArgError::Invalid));
    };

    let contract = if let Some(contract_id) = contract_id {
        if let Ok(contract_id) = contract_id.parse::<ContractId>() {
            contract_id
        } else {
            return Err(Box::new(ArgError::Invalid));
        }
    } else {
        ContractId::zeroed() // Current script
    };

    state
        .client
        .set_breakpoint(&state.session_id, contract, offset)
        .await?;

    Ok(())
}

async fn cmd_registers(state: &mut State, mut args: Vec<String>) -> Result<(), Box<dyn Error>> {
    args.remove(0);

    if args.is_empty() {
        for r in 0..VM_REGISTER_COUNT {
            let value = state.client.register(&state.session_id, r as u32).await?;
            let name = register_name(r);
            println!("reg[{:#x}] = {:<8} # {}", r, value, name);
        }
    } else {
        for arg in &args {
            if let Some(v) = parse_int(arg) {
                if v < VM_REGISTER_COUNT {
                    let value = state.client.register(&state.session_id, v as u32).await?;
                    let name = register_name(v);
                    println!("reg[{:#02x}] = {:<8} # {}", v, value, name);


                    if name == "hp" {
                        println!("heap size = {}", 2_u64.pow(26) - value);
                    }

                    if name == "sp" {
                        //println!("stack size = {}", value - )
                    }


                } else {
                    println!("Register index too large {}", v);
                    return Ok(());
                }
            } else if let Some(index) = names::register_index(arg) {
                let value = state
                    .client
                    .register(&state.session_id, index as u32)
                    .await?;
                println!("reg[{:#02x}] = {:<8} # {}", index, value, arg);


                if arg == "hp" {
                    println!("heap size = {}", 2_u64.pow(26) - value);
                }

            } else {
                println!("Unknown register name {}", arg);
                return Ok(());
            }
        }
    }

    Ok(())
}

async fn cmd_memory(state: &mut State, mut args: Vec<String>) -> Result<(), Box<dyn Error>> {
    args.remove(0);

    let limit = args
        .pop()
        .map(|a| parse_int(&a).ok_or(ArgError::Invalid))
        .transpose()?
        .unwrap_or(WORD_SIZE * (VM_MAX_RAM as usize));

    let offset = args
        .pop()
        .map(|a| parse_int(&a).ok_or(ArgError::Invalid))
        .transpose()?
        .unwrap_or(0);

    if !args.is_empty() {
        return Err(Box::new(ArgError::TooMany));
    }

    let mem = state
        .client
        .memory(&state.session_id, offset as u32, limit as u32)
        .await?;

    for (i, chunk) in mem.chunks(WORD_SIZE).enumerate() {
        print!(" {:06x}:", offset + i * WORD_SIZE);
        for byte in chunk {
            print!(" {:02x}", byte);
        }
        println!();
    }

    Ok(())
}

async fn cmd_frame(state: &mut State, mut args: Vec<String>) -> Result<(), Box<dyn Error>> {
    args.remove(0);

    if !args.is_empty() {
        return Err(Box::new(ArgError::TooMany));
    }

    let fp = state.client.register(&state.session_id, 0x06 as u32).await?;

    if fp == 0 {
        println!("Not in an external call");
        return Ok(())
    }

    let mem = state
        .client
        .memory(&state.session_id, fp as u32, 600 as u32)
        .await?;

    let to = Bytes32::new(mem[0..32].try_into().unwrap());
    let asset_id = Bytes32::new(mem[32..64].try_into().unwrap());

    println!("to        {}", to);
    println!("asset_id  {}", asset_id);

    println!("PREVIOUS_REGS :");
    
    for i in (64..576).step_by(8) {
        let reg  = u64::from_be_bytes(mem[i..i+8].try_into().unwrap());

        if reg != 0 {
            let r = (i-64)/8;
            let name = register_name(r);
            println!("{} 0x{:x}", name , reg);
        }
    }

    let codesize = u64::from_be_bytes(mem[576..584].try_into().unwrap());
    println!("codesize 0x{:x}", codesize);

    let param1 = u64::from_be_bytes(mem[584..592].try_into().unwrap());
    let param2 = u64::from_be_bytes(mem[592..600].try_into().unwrap());
    print!("param1 0x{:x}", param1);

    let len = state
        .client
        .memory(&state.session_id, param1 as u32, 8 as u32)
        .await?;

    let fn_name = state
        .client
        .memory(&state.session_id, (param1+8) as u32, u64::from_be_bytes(len[0..8].try_into().unwrap()) as u32)
        .await?;

    if fn_name.iter().all(|&c| c.is_ascii()) {
        unsafe {
            let ascii_string = String::from_utf8_unchecked(fn_name.to_vec());
            println!(" => \"{}\"", ascii_string);
        }
    } else {
        println!(" => non-ascii? {:?}", fn_name);
    }

    print!("param2 0x{:x}", param2);

    Ok(())
}




async fn cmd_code(state: &mut State, mut args: Vec<String>) -> Result<(), Box<dyn Error>> {
    args.remove(0);

    let limit = args
        .pop()
        .map(|a| parse_int(&a).ok_or(ArgError::Invalid))
        .transpose()?
        .unwrap_or( 4 * (10 as usize));

    let pc = state.client.register(&state.session_id, 0x03 as u32).await?;

    let offset = args
        .pop()
        .map(|a| parse_int(&a).ok_or(ArgError::Invalid))
        .transpose()?
        .unwrap_or((pc-4*9) as usize);

    if !args.is_empty() {
        return Err(Box::new(ArgError::TooMany));
    }

    let mem = state
        .client
        .memory(&state.session_id, offset as u32, limit as u32)
        .await?;

    let instructions = fuel_asm::from_bytes(mem.iter().cloned())
    .zip(mem.chunks(fuel_asm::Instruction::SIZE));

    let mut instructions = instructions.enumerate().peekable();

    while let Some((i, inst)) = instructions.next() {
        if offset + i * 4 == pc as usize {
            // This is the curret instruction
            print!("=> {:06x}:", offset + i * 4);
        } else {
            print!("   {:06x}:", offset + i * 4);
        }
        println!(
            " {:?}",
            inst.0.unwrap_or(
                RawInstruction::from_be_bytes([0x47, 0, 0, 0])
                    .try_into()
                    .unwrap()
            )
        );
    }

    Ok(())
}

fn parse_pattern(s: &str) -> Result<Vec<u8>, ArgError> {
    let s = s.trim();

    if let Some(stripped) = s.strip_prefix("0x") {
        // Hex string
        let s = stripped.replace('_', "");
        if s.len() % 2 != 0 {
            // Hex string must have an even number of characters
            return Err(ArgError::Invalid);
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ArgError::Invalid))
            .collect()
    } else {
        // Treat as ASCII string
        Ok(s.as_bytes().to_vec())
    }
}


async fn cmd_search_memory(state: &mut State, mut args: Vec<String>) -> Result<(), Box<dyn Error>> {
    args.remove(0); // Remove the command name

    // The pattern is mandatory
    let pattern_str = args.pop().ok_or(ArgError::NotEnough)?;

    // End address is optional
    let end = args
        .pop()
        .map(|a| parse_int(&a).ok_or(ArgError::Invalid))
        .transpose()?
        .unwrap_or(WORD_SIZE * (VM_MAX_RAM as usize));

    // Start address is optional
    let start = args
        .pop()
        .map(|a| parse_int(&a).ok_or(ArgError::Invalid))
        .transpose()?
        .unwrap_or(0);

    if !args.is_empty() {
        return Err(Box::new(ArgError::TooMany));
    }

    // Check that start <= end
    if start > end {
        return Err(Box::new(ArgError::Invalid));
    }

    // Parse the pattern
    let pattern = parse_pattern(&pattern_str)?;

    // Calculate the size to fetch
    let size = end - start;

    if size == 0 {
        return Err(Box::new(ArgError::Invalid));
    }

    // Fetch the memory
    let mem = state
        .client
        .memory(&state.session_id, start as u32, size as u32)
        .await?;

    // Search for pattern in mem
    let mut found = false;
    for (offset, window) in mem.windows(pattern.len()).enumerate() {
        if window == pattern.as_slice() {
            println!("Found pattern at address {:#x}", start + offset);
            found = true;
        }
    }

    if !found {
        println!("Pattern not found in the specified memory range.");
    }

    Ok(())
}


fn parse_int(s: &str) -> Option<usize> {
    let (s, radix) = if let Some(stripped) = s.strip_prefix("0x") {
        (stripped, 16)
    } else {
        (s, 10)
    };

    let s = s.replace('_', "");

    usize::from_str_radix(&s, radix).ok()
}
