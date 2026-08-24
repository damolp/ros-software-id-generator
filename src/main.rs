mod convert;
mod sha256;
mod sha256_constants;
mod software_id;
mod targets;

use std::convert::TryInto;
use std::path::PathBuf;

use crate::convert::hex_decode;
use crate::convert::hex_encode;
use crate::convert::key_text_to_signature;
use crate::convert::mt_base64_decode;
use crate::sha256::hash_40;
use crate::sha256_constants::ROUND_CONSTANTS;
use crate::software_id::encode;
use crate::targets::mix_from_identity;

use clap::{ArgGroup, Parser, ValueEnum};

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum DiskType {
    Nvme,
    Scsi,
    Ide,
}

#[derive(Parser, Debug)]
#[command(name = "checker", version, about = "Checks a file or a literal string")]
#[command(group(
  ArgGroup::new("input")
      .required(true)
      .args(["check", "check_string", "generate"]),
))]
struct Cli {
    #[arg(long, value_name = "FILE")]
    check: Option<PathBuf>,

    #[arg(long = "check-string", value_name = "STRING")]
    check_string: Option<String>,

    #[arg(long, requires_all = ["model", "serial", "size", "disk_type"])]
    generate: bool,

    #[arg(long, value_name = "STRING", requires = "generate")]
    model: Option<String>,

    #[arg(long, value_name = "STRING", requires = "generate")]
    serial: Option<String>,

    #[arg(long, value_name = "INT", requires = "generate")]
    size: Option<u32>,

    #[arg(long, value_name = "HEX", requires = "generate", value_parser = parse_hex10)]
    mbr: Option<[u8; 10]>,

    #[arg(long = "type", value_name = "TYPE", requires = "generate", value_enum)]
    disk_type: Option<DiskType>,
}

fn parse_hex10(s: &str) -> Result<[u8; 10], String> {
    let body = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);

    let digits: String = body
        .chars()
        .filter(|c| !c.is_whitespace() && !matches!(c, ':' | '-' | '_' | ','))
        .collect();

    if let Some(bad) = digits.chars().find(|c| !c.is_ascii_hexdigit()) {
        return Err(format!("invalid hex digit {bad:?}"));
    }
    if digits.len() % 2 != 0 {
        return Err(format!(
            "expected whole bytes, got {} hex digits",
            digits.len()
        ));
    }
    if digits.len() < 10 * 2 {
        return Err(format!(
            "expected at least 10 bytes, got {}",
            digits.len() / 2
        ));
    }

    let mut out = [0u8; 10];
    for (i, byte) in out.iter_mut().enumerate() {
        // digits are validated as ASCII hex above, so this cannot fail
        *byte = u8::from_str_radix(&digits[i * 2..i * 2 + 2], 16).unwrap();
    }
    Ok(out)
}

// called MT_Transform in some places
fn arx_permutate(block: &mut [u8; 16]) {
    let mut s = [0u32; 4];
    for (w, chunk) in s.iter_mut().zip(block.chunks_exact(4)) {
        *w = u32::from_be_bytes(chunk.try_into().unwrap());
    }

    for i in 0..16 {
        let (p, q, r, t) = (i % 4, (i + 1) % 4, (i + 2) % 4, (i + 3) % 4);
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
    assert!(
        sid[8..].iter().all(|&x| x == 0),
        " bits around the 16 byte block were not zero "
    );
    println!(
        "software_id: {}, ros: {}, level: {}",
        encode(software_id),
        ros_ver,
        level
    );
}

fn main() -> std::io::Result<()> {
    let cli = Cli::parse();
    if let Some(path) = cli.check.as_deref() {
        let contents = std::fs::read_to_string(path)?;
        return Ok(decode_license(
            hex_decode(&key_text_to_signature(&contents).unwrap()).unwrap(),
        ));
    } else if let Some(s) = cli.check_string.as_deref() {
        return Ok(decode_license(mt_base64_decode(&s).unwrap()));
    } else if cli.generate {
        let model = cli.model.as_deref().unwrap();
        let serial = cli.serial.as_deref().unwrap();
        let mut size = cli.size.unwrap();
        match cli.disk_type.unwrap() {
            DiskType::Nvme => size = size.next_multiple_of(16),
            DiskType::Scsi => size = 0,    // SCSI is 0
            DiskType::Ide => size = software_id::round_sectors((size / 512 >> 11) as u32),
        }
        let mut fp = [0x20u8; 40];
        fp[36..].fill(0); // zero out disk size

        let mbr = cli.mbr.unwrap_or([0u8; 10]);

        // serial
        let serial_len = serial.len().min(20);
        fp[0..serial_len].copy_from_slice(&serial.as_bytes()[..serial_len]);

        // Model
        let model_len = model.len().min(16);
        fp[20..20 + model_len].copy_from_slice(&model.as_bytes()[..model_len]);

        fp[36..].copy_from_slice(&size.to_le_bytes());

        println!("fingerprint str: '{}'", String::from_utf8_lossy(&fp));
        println!("fingerprint hex: '{}'", hex_encode(&fp));
        println!("mbr hex: '{}'", hex_encode(&mbr));

        let (sid_lo, sid_hi) = hash_40(&fp);

        let (mix_lo, mix_hi) = mix_from_identity(&mbr);

        let final_lo = sid_lo ^ mix_lo;
        let final_hi = ((sid_hi as u32) | 0x100) ^ mix_hi;

        let final_hash: u64 = ((final_hi as u64) << 32) | (final_lo as u64);

        println!("software-id: {}", encode(final_hash));
    }

    return Ok(());
}

#[cfg(test)]
  mod tests {
      use assert_cmd::Command;
      use predicates::str::contains;
  
      const BIN: &str = env!("CARGO_PKG_NAME");
  
      fn cmd() -> Command {
          Command::cargo_bin(BIN).expect("binary should be built by cargo test")
      }

      // MBR bit Zeroed Out - NVME
      // /dev/nvme0n1: hdd-model='QEMU NVMe Ctrl  ' s='vol-12345           ' sz=128 MB
      // F1U9-DYQW
      #[test]
      fn test_nvme_zeroed_mbr() {
          cmd()
              .args([
                  "--generate",
                  "--model", "QEMU NVMe Ctrl",
                  "--serial", "vol-12345",
                  "--size", "128",
                  "--type", "nvme"
              ])
              .assert()
              .success()
              .stdout(contains("F1U9-DYQW"));
      }

      // MBR bit Zeroed Out - SCSI
      // /dev/sda: hdd-model='1234            ' s='5678                ' sz=0 MB
      // BKT4-YM6W
      #[test]
      fn test_scsi_zeroed_mbr() {
          cmd()
              .args([
                  "--generate",
                  "--model", "1234",
                  "--serial", "5678",
                  "--size", "1000", // ignored
                  "--type", "scsi"
              ])
              .assert()
              .success()
              .stdout(contains("BKT4-YM6W"));
      }

    // MBR Set - NVME
    // /dev/nvme0n1: hdd-model='QEMU NVMe Ctrl  ' s='vol-1234            ' sz=128 MB
    // 0FIK-K9ZJ
    // mbr: `0100:  97 38 60 60 52 27 13 67 51 08 52 d0 00 00 00 00`

    #[test]
      fn test_nvme_set_mbr() {
          cmd()
              .args([
                  "--generate",
                  "--model", "QEMU NVMe Ctrl",
                  "--serial", "vol-1234",
                  "--size", "128",
                  "--type", "nvme",
                  "--mbr", "97 38 60 60 52 27 13 67 51 08 52 d0 00 00 00 00",
              ])
              .assert()
              .success()
              .stdout(contains("0FIK-K9ZJ"));
      }
    
    // /dev/nvme0n1: hdd-model='QEMU NVMe Ctrl  ' s='vol-1234            ' sz=138 MB
    // 9E8X-02NE
    // 0100:  97 38 60 60 52 27 13 67 51 08 52 d0 01 00 00 00 
    #[test]
      fn test_nvme_set_mbr_odd_size() {
          cmd()
              .args([
                  "--generate",
                  "--model", "QEMU NVMe Ctrl",
                  "--serial", "vol-1234",
                  "--size", "138",
                  "--type", "nvme",
                  "--mbr", "97 38 60 60 52 27 13 67 51 08 52 d0 00 00 00 00",
              ])
              .assert()
              .success()
              .stdout(contains("9E8X-02NE"));
      }

    // /dev/nvme0n1: hdd-model='QEMU NVMe Ctrl  ' s='MyReallyCoolNvmeSeri' sz=1272 MB
    // R1YJ-A7CK
    // 0100:  75 34 11 94 79 12 44 75 65 14 57 9b 02 00 00 00
    #[test]
      fn test_nvme_set_mbr_full_serial() {
          cmd()
              .args([
                  "--generate",
                  "--model", "QEMU NVMe Ctrl",
                  "--serial", "MyReallyCoolNvmeSeri",
                  "--size", "1272",
                  "--type", "nvme",
                  "--mbr", "75 34 11 94 79 12 44 75 65 14 57 9b 02 00 00 00",
              ])
              .assert()
              .success()
              .stdout(contains("R1YJ-A7CK"));
      }

    // /dev/nvme0n1: hdd-model='QEMU NVMe Ctrl  ' s='MyReallyCoolNvmeSeri' sz=1272 MB
    // 1CNM-CYSJ
    // 0100:  68 26 84 66 46 66 29 72 56 58 4e 42 00 00 00 00 
    #[test]
      fn test_scsi_set_mbr_full_serial() {
          cmd()
              .args([
                  "--generate",
                  "--model", "really-really-re",
                  "--serial", "12345678912345678900",
                  "--size", "1929292",
                  "--type", "scsi",
                  "--mbr", "68 26 84 66 46 66 29 72 56 58 4e 42 00 00 00 00",
              ])
              .assert()
              .success()
              .stdout(contains("1CNM-CYSJ"));
      }

    #[test]
      fn test_check_str() {
          cmd()
              .args([
                  "--check-string",
                  "mr3jH5qhn9irtF53ZICFTN7Tk7wIx7ZkxdAxJ19ydASYShhFteHMntBTyaS8wuNdIJJPidJxbuNPLTvCsv7zLA=="
              ])
              .assert()
              .success()
              .stdout(contains("TI09-7WK3"));
      }

      #[test]
      fn no_args_is_an_error() {
          cmd().assert().failure();
      }
  }

