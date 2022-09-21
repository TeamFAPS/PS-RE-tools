# ps-index-dat-tool

A PC program that transforms a PS3, PS Vita or PS4 index.dat file into a version.txt file or reciprocally.

## Usage

### Decryption

index-dat-tool index.dat version.txt

### Encryption

index-dat-tool -g key_rev index.dat version.txt

key_rev can be:
* 0: PS3
* 1: PS Vita System Software version 0.945.040 to 1.692.000
* 2: PS Vita System Software version 1.800.071 to 3.740.011
* 3: PS4

## TODO

* Add support for Windows (strangely does not run on Windows but runs in mingw64).
* Get rid of unnecessary libraries.

## Thanks

CelesteBlue, zecoxao, Team fail0verflow, Team Molecule
