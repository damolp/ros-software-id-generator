mod sha256;
mod convert;
mod software_id;
mod sha256_constants;

use std::convert::TryInto;
use std::path::PathBuf;

use crate::software_id::encode;
use crate::sha256_constants::ROUND_CONSTANTS;
use crate::convert::mt_base64_decode;
use crate::convert::key_text_to_signature;
use crate::convert::hex_decode;

use clap::{ArgGroup, Parser};

#[derive(Parser, Debug)]
#[command(name = "checker", version, about = "Checks a file or a literal string")]
#[command(group(
  ArgGroup::new("input")
      .required(true)
      .args(["check", "check_string"]),
))]

struct Cli {
  #[arg(long, value_name = "FILE")]
  check: Option<PathBuf>,

  #[arg(long = "check-string", value_name = "STRING")]
  check_string: Option<String>,
}



// called MT_Transform in some places
fn arx_permutate(block: &mut [u8; 16]) {
  let mut s = [0u32; 4];
  for (w, chunk) in s.iter_mut().zip(block.chunks_exact(4)) {
    *w = u32::from_be_bytes(chunk.try_into().unwrap());
  }

  for i in 0..16 {
      let (p, q, r, t) =  (i % 4, (i + 1) % 4, (i + 2) % 4, (i + 3) % 4);
      let k0 = ROUND_CONSTANTS[i * 4];
      let k1 = ROUND_CONSTANTS[i * 4 + 1];
      let k2 = ROUND_CONSTANTS[i * 4 + 2];
      let k3 = ROUND_CONSTANTS[i * 4 + 3];

      // `k & 0x0F` is always 0..=15, so `rotate_left` can never overflow.
      s[r] = s[r].wrapping_sub(s[p]).wrapping_sub(k0);
      s[t] = (s[p].rotate_left(k0 & 0x0F) ^ s[t]).wrapping_add(s[p]);

      s[q] = s[q].wrapping_sub(s[t]).wrapping_sub(k1);
      s[r] = (s[q].rotate_left(k1 & 0x0F) ^ s[r]).wrapping_add(s[q]);

      s[p] = s[p].wrapping_sub(s[r]).wrapping_sub(k2);
      s[q] = (s[r].rotate_left(k2 & 0x0F) ^ s[q]).wrapping_add(s[r]);

      s[t] = s[t].wrapping_sub(s[q]).wrapping_sub(k3);
      s[p] = (s[t].rotate_left(k3 & 0x0F) ^ s[p]).wrapping_add(s[t]);
  }

  for (chunk, w) in block.chunks_exact_mut(4).zip(s.iter()) {
    chunk.copy_from_slice(&w.to_be_bytes());
  }

}

fn decode_license(buffer: Vec<u8>) {
    let mut sid = [0u8; 16];
    sid.copy_from_slice(&buffer[0..16]);
    arx_permutate(&mut sid);
    let software_id = u64::from_le_bytes(sid[..8].try_into().unwrap()) & 0x0000_FFFF_FFFF_FFFF;
    let ros_ver = sid[6];
    let level = sid[7];
    assert!(sid[8..].iter().all(|&x| x == 0), " bits around the 16 byte block were not zero ");
    println!("software_id: {}, ros: {}, level: {}", encode(software_id), ros_ver, level);
}

fn main() -> std::io::Result<()> {
    let cli = Cli::parse();
    if let Some(path) = cli.check.as_deref() {
          let contents = std::fs::read_to_string(path)?;
          return Ok(decode_license(hex_decode(&key_text_to_signature(&contents).unwrap()).unwrap()));
      } else if let Some(s) = cli.check_string.as_deref() {
          return Ok(decode_license(mt_base64_decode(&s).unwrap()));
      }
    return Ok(());
}