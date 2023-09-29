# ps-index-dat-tool

A PC program that transforms a PS3, PS Vita or PS4 index.dat file into a version.txt file or reciprocally.

## Usage

### Decryption

ps-index-dat-tool index.dat version.txt

### Encryption

ps-index-dat-tool -g key_rev index.dat version.txt

key_rev can be:
* 0: PS3
* 1: PS Vita 0.931.010-1.692.000
* 2: PS Vita 1.800.030-3.740.011
* 3: PS4

## Thanks

CelesteBlue, zecoxao, Team fail0verflow, Team Molecule