# PWN105 CTF Walkthrough

## Executive Summary

This is an integer overflow vulnerability challenge. The program asks for two integers to add, but does not properly validate the result. By providing values that cause integer overflow, the result becomes negative, triggering hidden code that executes a shell command.

---

## Phase 1: Reconnaissance

### 1.1 File Information

**Target Binary:** `/home/jack/Documents/hacktivities/projects/pwn ctfs/pwn105/pwn105`

**File Type Analysis:**
```
ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked
PIE enabled (ASLR resistant)
Not stripped (symbols available)
```

### 1.2 Security Protections Analysis

Using `checksec`:

| Protection | Status | Notes |
|-----------|--------|-------|
| **RELRO** | Partial RELRO | Standard for PIE |
| **Stack Canary** | ✅ Found | Stack protected |
| **NX** | ✅ Enabled | No code execution on stack |
| **PIE** | ✅ Enabled | Address space randomization |
| **Stripped** | ❌ No | Symbols visible |

### 1.3 Program Behavior

```
Title: "BAD INTEGERS"
"Enter two numbers to add"
Prompt: "]>> "
Reads two integers via scanf
Adds them together
Displays result
```

**Key String:** `[*] Popped Shell` and `[*] Switching to interactive mode`

This suggests a hidden code path that spawns a shell.

---

## Phase 2: Binary Analysis

### 2.1 Main Function Logic

```assembly
00000000000124e <main>:
  124e: 55                    push   %rbp
  124f: 48 89 e5              mov    %rsp,%rbp
  1252: 48 83 ec 20           sub    $0x20,%rsp        # Stack canary setup
  1256-125f: [canary setup]
  1265: b8 00 00 00 00        mov    $0x0,%eax
  126a: e8 1a ff ff ff        call   1189 <setup>
  1274: e8 98 ff ff ff        call   1211 <banner>
  1279-12c1: [printf/scanf for first number]
  12c6-12f0: [printf/scanf for second number]
  12f5: 8b 55 ec              mov    -0x14(%rbp),%edx   # Load first number
  12f8: 8b 45 f0              mov    -0x10(%rbp),%eax   # Load second number
  12fb: 01 d0                 add    %edx,%eax         # ADD OPERATION
  12fd: 89 45 f4              mov    %eax,-0xc(%rbp)   # Store result
  1300: 8b 45 ec              mov    -0x14(%rbp),%eax   # Load first number
  1303: 85 c0                 test   %eax,%eax         # Test if negative
  1305: 78 7d                 js     1384 <main+0x136> # Jump if negative
  1307: 8b 45 f0              mov    -0x10(%rbp),%eax   # Load second number
  130a: 85 c0                 test   %eax,%eax         # Test if negative
  130c: 78 76                 js     1384 <main+0x136> # Jump if negative
  130e: 83 7d f4 00           cmpl   $0x0,-0xc(%rbp)   # Test if result negative
  1312: 78 37                 js     134b <main+0xfd>  # Jump if result is negative
  1314-1349: [Normal path - print positive result]
  134b: 8b 45 f4              mov    -0xc(%rbp),%eax   # Load result (negative!)
  134e: 89 c6                 mov    %eax,%esi
  1350-135a: [setup printf]
  135f: e8 fc fc ff ff        call   1060 <printf@plt> # Print result
  1364-136b: [load string]
  136e: e8 bd fc ff ff        call   1030 <puts@plt>   # Print "[*] Popped Shell"
  1373-137a: [load /bin/sh string]
  137d: e8 ce fc ff ff        call   1050 <system@plt> # SHELL EXECUTION!
```

### 2.2 Vulnerability: Integer Overflow

**The Key Vulnerability:**

1. Two 32-bit signed integers are read
2. They are added together using 32-bit arithmetic
3. If the sum exceeds INT32_MAX (2,147,483,647), it overflows
4. The result wraps around and becomes negative
5. At 0x130e, the code checks if the result is negative
6. If negative, it jumps to 0x134b which calls `system("/bin/sh")`

**Critical Check:**
```assembly
130e: cmpl $0x0,-0xc(%rbp)    # Compare result with 0
1312: js 134b                  # Jump to shell code if result is NEGATIVE
```

### 2.3 Stack Layout

```
RBP - 0x8      ← Canary
RBP - 0xc      ← Result (signed 32-bit int)
RBP - 0x10     ← Second number (signed 32-bit int)
RBP - 0x14     ← First number (signed 32-bit int)
RBP + 0x0      ← Frame Pointer
```

---

## Phase 3: Exploitation

### 3.1 Integer Overflow Strategy

**Goal:** Make the addition result negative

**Method:** Add two numbers whose sum exceeds INT32_MAX

**Calculation:**
- INT32_MAX = 2,147,483,647
- If we add: 2,147,483,647 + 100 = 2,147,483,747
- In 32-bit signed arithmetic, this wraps to: -2,147,483,549

**Formula:**
```
result = (a + b) & 0xFFFFFFFF
if result >= 2^31:
    result -= 2^32  # Convert to signed
```

### 3.2 Payload Structure

Simply provide two numbers that overflow:

```
First number:  2147483647  (INT32_MAX)
Second number: 100         (any positive number works)
```

This causes overflow:
- 2147483647 + 100 = 2147483747
- Wraps to negative: -2147483549
- Code detects negative result
- Executes system("/bin/sh")

### 3.3 Why This Works

The programmer made two mistakes:

1. **Input Validation:** No check to prevent negative results from overflow
2. **Logic Error:** When result is negative, instead of error handling, the code calls `system("/bin/sh")`

The negative result check at 0x130e is meant as a validation, but it actually triggers the shell code instead of rejecting it.

---

## Phase 4: Protection Analysis

**Why Standard Protections Don't Help:**

| Protection | Effect | Why Ineffective |
|-----------|--------|-----------------|
| **Stack Canary** | Detects buffer overflow | Not triggered - no buffer overflow |
| **NX** | Prevents code on stack | Not needed - calls existing `system()` |
| **PIE** | Randomizes addresses | `system()` called through PLT, works anyway |
| **RELRO** | Protects GOT | Can't modify anyway |

The vulnerability is **logical**, not memory corruption. No protection can prevent incorrect program logic.

---

## Phase 5: Key Learnings

| Concept | Explanation |
|---------|------------|
| **Integer Overflow** | When operation exceeds max value, result wraps around |
| **Signed vs Unsigned** | Signed 32-bit: -2^31 to 2^31-1; Overflow wraps to negative |
| **Input Validation** | Critical to check input ranges and operation results |
| **Logic Errors** | Bad comparisons/conditions can bypass security |
| **Unintended Code Paths** | Hidden functionality triggered by edge cases |

---

## Phase 6: Differences from Previous Challenges

| Feature | PWN101 | PWN102 | PWN103 | PWN104 | PWN105 |
|---------|--------|--------|--------|---------|---------|
| Vuln Type | Overflow | Overflow | Overflow+ROP | Shellcode | Integer Overflow |
| Protection | None | None | None | Disabled NX | All Enabled |
| Exploitation | Memory corruption | Memory manipulation | ROP chain | Info leak | Logic bug |
| Canary | No | No | No | No | **Yes** |
| NX | Yes | Yes | Yes | **No** | Yes |
| PIE | Yes | Yes | No | No | **Yes** |
| Input Method | gets() | scanf() | scanf() | read() | scanf() |
| Difficulty | Beginner | Intermediate | Advanced | Advanced | Intermediate |

---

## Phase 7: Exploitation Steps

1. Run the binary
2. At first prompt, enter: `2147483647`
3. At second prompt, enter: `100`
4. Program detects integer overflow (negative result)
5. Instead of error, calls `system("/bin/sh")`
6. Interactive shell spawned
7. Win!

---

## Commands Reference

```bash
checksec --file=./pwn105
objdump -d ./pwn105 | grep -A 80 "<main>:"
strings ./pwn105 | grep "Popped"
```

---

## Conclusion

This challenge highlights the importance of logical security, not just memory safety. Modern protections like canaries, NX, and PIE are all enabled, yet the program is still compromised due to a simple integer overflow logic bug. The lesson: secure input validation and correct conditional logic are as important as low-level memory protections.
