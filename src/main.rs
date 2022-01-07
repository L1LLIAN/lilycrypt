use std::str::FromStr;

use clap::Parser;

#[derive(Debug)]
enum Mode {
    Encrypt,
    Decrypt,
}

impl FromStr for Mode {
    type Err = std::io::Error;

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

fn main() {
    let args = Args::parse();

    println!("args = {:?}", args);
}
