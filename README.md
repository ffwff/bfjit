# bfjit

Experiments I did making JIT brainfuck interpreter targeting the x86-64 architecture.

## Optimizations

The program parses a brainfuck file and transforms it into an x86-64 function `void _bfjit(uint8_t *tape)`, which is then called. Upon execution, `%rdi` is set to the address of the tape and `%rcx` is set to the starting position (`0x00`). I'll use the GAS/AT&T syntax as assembly notation.

### Exploiting x86 registers

The original brainfuck compiler was written with wraparound behavior: if the current position of the pointer is 0, and we decrement it, it would become the maximum position of the tape (30000). Doing bounds checking and manual wraparound would be too expensive, even more so when the tape length, 30000, [is not a power of 2](https://stackoverflow.com/questions/11040646/faster-modulus-in-c-c).

Which was one of the reasons I increased the tape size to 65536, the maximum value of a 16-bit integer. x86-64 actually provides us with several 16-bit general purpose registers we can use (`%ax`, `%cx`, `%dx`, and `%bx`). If we add an integer to one of these registers, and it overflows, it will wraparound back to 0. In `bfjit-64k*.c`, I used this trick and made the `%cx` register store our pointer position.

### Fusing value changes

If there is a consecutive series of `+` or `-`, we can calculate the summed delta of the series (`+` being 1 and `-` being -1), and add that to the value in tape instead. So a chain of `+++-`, instead of becoming,

```
incb (%rcx,%rdi,1)
incb (%rcx,%rdi,1)
incb (%rcx,%rdi,1)
decb (%rcx,%rdi,1)
```

it would become,

```
addb $0x2, (%rcx, %rdi,1)
```

### Fusing pointer changes

Similarly, if there is a consecutive series of `>` or `<`, we can calculate the summed delta and add that to the tape position. Instead of `>>>` becoming

```
inc %cx
inc %cx
inc %cx
```

it would become,

```
add $0x3, %cx
```

### Postponing movements

If there is a series of bf commands containing only `+`, `-`, `>`, `<`, we can keep track of pointer movements and add them in one shot once there is a `[`, `]`, `.` or `,` command. So from `>+++>` instead of becoming,

```
inc %cx
addb $0x3, (%rcx, %rdi, 1)
inc %cx
```

would become

```
addb $0x3, 0x1(%rcx, %rdi, 1)
addb $0x3, %cx
```

Postponing movements are implemented in `bfjit-64k-postpone.c`, however it is very buggy (it doesn't run `hanoi.b` correctly), posibbly due to x86 opcodes being a mess.

### Clear loops

If there is a series of `[-]`, we simply just clear the value in that location in tape:

```
movb $0x0, (%rcx, %rdi, 1)
```

If there is a series of `+` or `-` following it, instead of clearing, we set the value to the summed delta, so `[-]+++` becomes

```
movb $0x3, (%rcx, %rdi, 1)
```

Several programs chain clear loops, we can make these chained clears faster by bitmasking the 64-bit value starting from the current position in tape with a calculated mask. So `[-]>[-]>[-]` becomes

```
mov $0x0, (%rcx, %rdi, 1)
and $0xffff0000, (%rcx, %rdi, 1)
```

### Simple loops

If the loop body has no subloops and no input/output, all the movements add up to 0, and all the increments/decrements at the current location in tape add up to −1, we can remove the loop jumps and condition checks, and transform all value changes inside the loop to be a multiple of the value at the current location in tape.


## Implementation notes

* Although the interpreter allows the tape pointer to be wrapped around, one can easily place a "simple loop" or chained clear loops to overflow the buffer, This can be fixed by doing proper bounds checking (which would defeat the point of these optimizations) or using [funky memory maps](https://nullprogram.com/blog/2016/04/10/) and limiting optimization pointer movements.
* This interpreter doesn't use an IR to translate, it directly translates bf to x86-64 opcodes. Using an IR would tremendously help development time and open up to new architecture possibilites. However, i'm too lazy.

