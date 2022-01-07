use std::{fs, io, path::Path, str::FromStr};

use clap::Parser;

use aes::cipher::{generic_array::GenericArray, BlockDecrypt, NewBlockCipher};
use aes::{Aes256, Block, BlockEncrypt};

#[derive(Debug)]
enum Mode {
    Encrypt,
    Decrypt,
}

impl FromStr for Mode {
    type Err = io::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let lowercase = s.to_lowercase();
        if lowercase == "encrypt" {
            return Ok(Mode::Encrypt);
        }

        if lowercase == "decrypt" {
            return Ok(Mode::Decrypt);
        }

        panic!("Invalid mode!");
    }
}

#[derive(Parser, Debug)]
#[clap(about, version, author)]
struct Args {
    /// The mode for the program to run with, Can either be encrypt or decrypt
    #[clap(short, long)]
    mode: Mode,

    /// The input file to be encrypted or decrypted
    #[clap(short, long)]
    input: String,

    /// The file to save the output to
    #[clap(short, long)]
    output: String,

    /// The password used to encrypt the file
    #[clap(short, long)]
    password: String,
}

fn main() -> io::Result<()> {
    let args = Args::parse();

    let input_file_path = Path::new(&args.input);
    let output_file_path = Path::new(&args.output);
    if !input_file_path.exists() {
        println!(
            "Invalid input file path!, Path {} doesn't exist!",
            &args.input
        );
        return Ok(());
    }

    if output_file_path.exists() {
        println!(
            "Found existing file at {}, this file will be overwritten!",
            &args.output
        );
    }

    let password_len = args.password.as_bytes().len();
    if password_len != 32 {
        println!(
            "Invalid password! Must be 32 bytes, Current size = {}",
            password_len
        );
        return Ok(());
    }

    match args.mode {
        Mode::Encrypt => encrypt(input_file_path, output_file_path, args.password)?,
        Mode::Decrypt => decrypt(input_file_path, output_file_path, args.password)?,
    };

    println!("Done!");
    Ok(())
}

fn encrypt(input: &Path, output: &Path, password: String) -> io::Result<()> {
    if output.exists() {
        fs::remove_file(output)?;
    }

    let input_file_content = fs::read(input)?;

    let key = GenericArray::from_slice(password.as_bytes());
    let cipher = Aes256::new(key);

    let blocks = get_blocks(input_file_content);

    let mut encoded = String::new();
    for mut block in blocks {
        cipher.encrypt_block(&mut block);
        encoded.push_str(&hex::encode(block));
    }

    fs::write(output, encoded)?;

    Ok(())
}

fn decrypt(input: &Path, output: &Path, password: String) -> io::Result<()> {
    if output.exists() {
        fs::remove_file(output)?;
    }

    let input_file_content = fs::read(input)?;
    let decoded = hex::decode(input_file_content).expect("Error decoding input file");

    let key = GenericArray::from_slice(password.as_bytes());
    let cipher = Aes256::new(key);

    let blocks = get_blocks(decoded);

    let mut decrypted: Vec<u8> = Vec::new();
    for mut block in blocks {
        cipher.decrypt_block(&mut block);
        decrypted.append(&mut block.to_vec());
    }

    fs::write(output, &decrypted.as_slice())?;

    Ok(())
}

fn get_blocks(vec: Vec<u8>) -> Vec<Block> {
    let mut index = 0;
    let mut blocks: Vec<Block> = Vec::new();

    loop {
        index += 16;

        let mut diff = 0;
        if index > vec.len() {
            diff = index - vec.len();
            index = vec.len();
        }

        let mut slice = &vec[index - 16 + diff..index];
        let mut slice_vec = Vec::from(slice);
        slice_vec.resize(16, b'\0');
        slice = slice_vec.as_slice();

        let block = Block::from_slice(slice);
        blocks.push(*block);

        if index == vec.len() {
            break;
        }
    }

    blocks
}
