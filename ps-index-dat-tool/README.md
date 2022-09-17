# ps-index-dat-tool

A program to decrypt or encrypt PS3, PS Vita or PS4 index.dat file.

## Usage

### Decryption

index-dat-tool index.dat version.txt

### Encryption

index-dat-tool -g key_rev index.dat version.txt

key_rev can be:
* 0: PS3
* 1: PS Vita 0.990-1.692
* 2: PS Vita 1.80-3.74
* 3: PS4

## TODO

* Add support for Windows (strangely does not run on Windows but works in mingw64).
* Get rid of unnecessary libraries.

## Thanks

CelesteBlue, zecoxao, Team fail0verflow, Team Molecule