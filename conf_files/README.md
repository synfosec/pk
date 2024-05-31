# Configuration

## Configuration Files

- `conf_files/remote.py` - Configuration for remote exploitation
- `conf_files/binary.py` - Configuration for binary exploitation
- `conf_files/payload.py` - Configuration for outputting payload to a file
- `conf_files/pack.py` - Configuration for generating shellcode from `shellcode.asm` file in current working directory

## Shellcode Generation

#### `shellcode.asm`

To generate shellcode from the shellcode.asm file, edit the file and write intel assembly code

Example:

```asm
mov eax, 0x1388
```

Run

```
$ python pk.py --shellcode_generate
```

This will generate shellcode from the `shellcode.asm` file and output it to the console

## Payload Generation

To generate payload just put the shellcode in `payload` variable in `conf_files/payload.py` file then run

```sh
$ python pk.py --payload_create [FILE NAME]
```

## Disassembling Shellcode

You can output your shellcode using the `--payload_create` command. After creating a payload file, you can disassemble it using the following command:

```sh
$ python pk.py --disasm [FILE NAME]
```

## Searching for exploits

Search for exploits doing the following command

```sh
$ python pk.py --db ubuntu22
```
