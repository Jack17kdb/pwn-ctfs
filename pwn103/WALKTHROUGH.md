# PWN103 CTF Walkthrough

## Executive Summary

This is a buffer overflow challenge that exploits a hidden admin function. By overflowing a 32-byte buffer in the general() function, we can call the hidden `admins_only()` function which executes `system("/bin/sh")`, bypassing normal access restrictions.

---

## Phase 1: Reconnaissance

### 1.1 File Information

**Target Binary:** `/home/jack/Documents/hacktivities/projects/pwn ctfs/pwn103/pwn103`

**File Type Analysis:**
```
ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked
Not PIE (0x400000)
Not stripped (symbols available)
```

### 1.2 Security Protections Analysis

Using `checksec`:

| Protection | Status | Notes |
|-----------|--------|-------|
| **RELRO** | Partial RELRO | Allows GOT modification |
| **Stack Canary** | ❌ Not Found | **VULNERABLE** |
| **NX** | ✅ Enabled | Code execution limited |
| **PIE** | ❌ No | Fixed addresses |
| **Stripped** | ❌ No | Symbols visible |

---

## Phase 2: Binary Analysis

### 2.1 Program Structure

Discord-like menu system with 5 options:
1. Announcements
2. Rules
3. General chat
4. Rooms discussion
5. Bot commands

Option 3 (General) has the vulnerable buffer overflow.

### 2.2 Vulnerable general() Function

```assembly
00000000004012be <general>:
  4012be: 55                    push   %rbp
  4012bf: 48 89 e5              mov    %rsp,%rbp
  4012c2: 48 83 ec 20           sub    $0x20,%rsp        # 32-byte buffer
  401316: 48 8d 45 e0           lea    -0x20(%rbp),%rax  # Buffer location
  40131a: 48 89 c6              mov    %rax,%rsi
  40131d: 48 8d 05 38 11 00 00  lea    0x1138(%rip),%rax
  401324: 48 89 c7              mov    %rax,%rdi
  40132c: e8 6f fd ff ff        call   4010a0 <__isoc99_scanf@plt>
```

**Vulnerability:** `scanf("%s")` reads into a 32-byte buffer with no bounds checking.

### 2.3 Hidden admins_only() Function

```assembly
0000000000401554 <admins_only>:
  401554: 55                    push   %rbp
  401555: 48 89 e5              mov    %rsp,%rbp
  401558: 48 83 ec 10           sub    $0x10,%rsp
  40155c-401575: [puts output]
  401584: e8 c7 fa ff ff        call   401050 <system@plt>
```

This function is not reachable through normal menu flow but contains a call to `system()` with `/bin/sh`.

### 2.4 Stack Layout in general()

```
RBP + 0x8      ← Return Address
RBP + 0x0      ← Frame Pointer
RBP - 0x20     ← Buffer (32 bytes)
```

Offset to return address: 32 + 8 = **40 bytes**

---

## Phase 3: Exploitation

### 3.1 Hidden Function Strategy

The `admins_only()` function exists in the binary but is never called through normal control flow. By overflowing the buffer and controlling the return address, we can force execution to jump to this function.

### 3.2 ROP Chain

The exploit uses two gadgets:

1. **Ret gadget at 0x401016:**
   ```assembly
   401016: c3  ret
   ```
   This ensures proper stack alignment for x86-64 calling convention.

2. **admins_only() at 0x401554:**
   Executes `system("/bin/sh")`

### 3.3 Payload Structure

```
[40 bytes padding]
[0x401016 - ret gadget]
[0x401554 - admins_only function]
```

**Execution:**
1. `scanf()` overflows buffer with payload
2. Function returns to 0x401016 (ret gadget)
3. Ret pops 0x401554 from stack
4. Control jumps to `admins_only()`
5. Shell spawned via `system("/bin/sh")`

### 3.4 Stack Alignment

The ret gadget is essential because x86-64 requires RSP to be 16-byte aligned before a `call` instruction. This ensures the stack is in the correct state for `admins_only()` to execute properly.

---

## Phase 4: Key Learnings

| Concept | Explanation |
|----------|------------|
| **Hidden Functions** | Unused code can exist but still be exploitable |
| **ROP Gadgets** | Short code sequences chained for control flow hijacking |
| **Stack Alignment** | x86-64 requires 16-byte RSP alignment |
| **Return Address** | Overwriting it changes execution flow |
| **No PIE** | Fixed addresses make exploitation deterministic |

---

## Differences from Previous Challenges

| Feature | PWN101 | PWN102 | PWN103 |
|---------|--------|--------|--------|
| Vuln Type | Buffer Overflow | Buffer Overflow | Buffer Overflow + ROP |
| Input Function | gets() | scanf() | scanf() |
| Buffer Size | 64 bytes | 112 bytes | 32 bytes |
| Exploitation | Direct overflow | Offset calculation | ROP chain |
| Hidden Code | No | No | Yes (admins_only) |
| PIE | Yes | Yes | No |
| Difficulty | Beginner | Intermediate | Advanced |
