# ros-software-id-generator

Basically a tool that will generate permutations of Mikrotik Software IDs (Basically `keyman` which is shipped with MikroTik software, but an open source version).

Reverse Engineering is my own work based off of MikroTik's `keyman` utility, cross referenced with other GitHub repos.

Forked from [cheebun/ros-serialgen](https://github.com/cheebun/ros-serialgen)

# Why?

Why not? I was interested at how MikroTik licensing works before I commit to buying some licenses for their software to replace some physical MikroTik hardware that I have.

Physical MikroTik hardware is licensed for life, but purchasing a license for a VirtualMachine seems scarier as I could potentially lose my few thousand dollars of licensing migrating between Cloud providers, so I wrote these tools to look at exactly how they license their software.


## TODO
* Actual license validation against the Mikrotik Public Key, right now we just decode

## Example Usage
* Check a serial file (`--check`):
```
$ rosgen --check test.key
software_id: G353-EXPG, ros: 7, level: 6
```

* Check a serial string (`--check-string`)
```
$ rosgen --check-string "mr3jH5qhn9irtF53ZICFTN7Tk7wIx7ZkxdAxJ19ydASYShhFteHMntBTyaS8wuNdIJJPidJxbuNPLTvCsv7zLA=="
software_id: TI09-7WK3, ros: 6, level: 6
```

* Generate a system ID for a nvme host (see unit tests for more examples)
```
$ rosgen --generate --model "QEMU NVMe Ctrl" --serial "serial" --size 1234 --type nvme         
fingerprint str: 'serial              QEMU NVMe Ctrl  �'
fingerprint hex: '73657269616C202020202020202020202020202051454D55204E564D65204374726C2020E0040000'
mbr hex: '00000000000000000000'
software-id: NI7X-CY6U
```

* Check if a generated "vanity style" software id is possible
```
$ rosgen --generate-id --software-id "DAM0-NET2"
final_lo: 0xc8015d36, final_hi: 0x1df
mix_lo: 0xf3a18b13, mix_hi: 0x2
sid_lo: 0x3ba0d625, sid_hi: 0xdd
software id (encoded): DAM0-NET2
softwareid (computed): DAM0-NET2
```

* Check if a lo / hi combo is valid:
```
$ rosgen --check-id --lo 0x100 --hi 0x10
software-id: 3EY6-YA4G
```