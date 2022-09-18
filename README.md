# PS Reverse Engineering Tools
by FAPS Team (and other developers if they add their tools there)

Every tool provided here will be licensed under GPLv3.0 unless stated otherwise.

What is this?

This toolkit provides tools that aid in the development of PS homebrews and plugins, as well as PC tools and even emulators, by providing tools that speed up development through automation of processes and gives a more friendly view into complex things of PS OS.

These tools heavily contribute to Wiki and open source SDK improvements.

*** Remember: IF YOU DO NOT UNDERSTAND WHAT THESE TOOLS DO, IT MAY NOT BE FOR YOU! ***

## Description of the tools

ps-flash-extract (PSP2, PS4) - by @CelesteBlue-dev
---
A PC program that extracts partitions from a PS Vita internal eMMC dump or a PS4 serial flash dump.

ps-nids-extract (PSP, PS3, PSP2) - by @CelesteBlue-dev
---
A PC program that extracts from a PS ELF a list in YAML format of exported NIDs. PSP and PS3 support will be added.

ps-index-dat-tool (PS3, PSP2, PS4) - by @CelesteBlue-dev
---
A PC program that transforms a PS3, PS Vita or PS4 index.dat file into a version.txt file or reciprocally.

--------------------------------------------------------------------------------

## Using the Tools

ps-nids-extract usage
---
A db yaml will be generated to stdout using the exports of a specified ELF. You will need to specify a version to be inserted to yaml such as "3.60", which is shown in the following example.

#### For a single file:

	ps-nids-extract <FW version> <binary name>.elf > <output filename>.yml

Example:

	ps-nids-extract.exe 3.60 kd/acmgr.elf > acmgr.yml
	
#### For multiple files in one command in terminal:

	./ps-nids-extract 3.60 $(find decrypted -name '*.elf' -not -path "./app/*") > db_lookup.yml`

or better:

	./ps-nids-extract 3.60 $(find 360_fw/fs_dec -type f -name '*.elf' ! -name eboot.elf ! -path '*/sm/*.elf') > db_lookup.yml

--------------------------------------------------------------------------------

## Further thanks

(TODO)
