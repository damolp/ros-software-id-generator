# ros-software-id-generator

Basically a tool that will generate permutations of Mikrotik Software IDs (Basically `keyman` which is shipped with MikroTik software, but an open source version).

Reverse Engineering is my own work based off of MikroTik's `keyman` utility, cross referenced with other GitHub repos.

Forked from [cheebun/ros-serialgen](https://github.com/cheebun/ros-serialgen)


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
