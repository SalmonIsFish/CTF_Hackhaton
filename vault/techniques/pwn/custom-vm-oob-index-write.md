# Custom bytecode VM: register-checked-but-offset-unchecked LOAD/STORE

**Category**: Binary exploitation / reverse engineering (custom VM)
**Signal**: A challenge ships its own tiny bytecode interpreter ("VM", "sandboxed machine",
"esoteric language") with fixed-size registers and a fixed-size memory array, reachable over
`nc`. The binary is small, not stripped, and the interpreter loop lives directly in `main`
(no separate `execute()`/`step()` function) as a jump-table `switch` over a 1-byte opcode.

## The technique

VM opcodes that take an **immediate offset in addition to a register-held index** are a classic
place for an off-by-a-bounds-check bug: the implementation validates the register's value (e.g.
"index must be 0-255" to match a documented "256 memory cells") but then adds the instruction's
raw immediate field to that already-validated value **before** using it to compute the final
address — with no second bounds check on the sum. Any single-register-indexed
LOAD/STORE-with-displacement opcode is worth disassembling byte-for-byte to check this,
especially if the ISA also has a *separate*, more heavily-checked "safe" LOAD/STORE opcode with
no immediate (a strong signal the immediate variant is the one that got the check wrong,
possibly deliberately as the intended bug).

Because interpreters like this usually store **all** VM state — registers, memory cells, and any
internal function pointers/callbacks — in one contiguous heap buffer addressed via a single
`base + index*8` formula, an unchecked-offset LOAD/STORE is an arbitrary read/write relative to
that buffer, not just an overflow into adjacent memory cells. Look for anything callable stored
in that same buffer (a "syscall"/"hook"/"extension" opcode that `call`s a function pointer loaded
from the state struct is a very common design for giving the VM I/O capability) — overwriting
that pointer turns the OOB write into arbitrary code execution within the process, using
functions that already exist in the binary (e.g. a flag-printing function never normally
reachable from the VM's own instruction set).

## Recon checklist

- [ ] Disassemble the fetch/decode/dispatch loop first (`aaa; pdf @ main` in radare2, or find the
      jump-table `switch`) to learn the fixed instruction encoding (opcode size, operand count,
      immediate size/position) — everything else depends on getting this exactly right.
- [ ] For every opcode that touches the "memory" array, check: is the final address `index*8`
      (register value only) or `(index + imm)*8` / `(index + imm + offset)*8`? The latter is the
      one to scrutinize.
- [ ] Compare against any "safe" sibling opcode doing the same operation without an immediate —
      if the safe one re-validates fully (`cmp reg, MAX; ja error`) and the offset one only
      validates the register-only part, that confirms the gap.
- [ ] Map the VM state struct's full layout (registers, memory cells, then whatever comes after —
      function pointers, length/pc fields, the raw bytecode buffer). A not-stripped binary's
      symbol names (e.g. a `hook_default`/`emit_flag`-style pair) usually make the intended
      target obvious.
- [ ] If a function pointer lives in the state buffer and there's an opcode that calls it, that's
      almost always the intended exploitation path: leak the pointer's current value with an OOB
      *read* (gives the binary's runtime load base, since the pointer's static offset is known
      from symbols), compute the target function's runtime address from that leak plus the fixed
      static delta between the two symbols, then OOB *write* it back over the pointer, then
      trigger the call opcode.
- [ ] Check the target function's calling convention/signature against what the call site actually
      passes — if the hijacked call site passes different args than the target function reads (or
      the target ignores its args entirely, as a `void foo(void)` disguised as taking params
      often does), it'll still work fine; only worry about this if the target function actually
      dereferences an argument register that will hold garbage.

## Example (worked instance)

`SANDWORM VM` — 8-byte instructions (`opcode:1, reg_a:1, reg_b:1, pad:1, imm:i32`), 16 registers
+ 256 memory cells + a `hook_default` function pointer, all in one `calloc`'d struct addressed as
`base + index*8`. Opcodes `LOAD reg_a, mem[reg_b + imm]` and `STORE mem[reg_a + imm], reg_b`
validated `reg[reg_a]`/`reg[reg_b]` (the register-held index) against `0xff`, but never
re-validated after adding `imm` — while a separate, correctly-bounds-checked pair (`LOAD_SAFE`/
`STORE_SAFE`, no immediate) existed right next to them for comparison. `imm=256` with the index
register holding `0` lands exactly on the `hook_default` pointer's offset. Leaked it via OOB LOAD
(→ PIE base), computed `emit_flag`'s runtime address via the fixed static delta between the two
symbols, OOB-STOREd it over the pointer, then triggered the VM's `HOOK` opcode (which calls that
pointer) to run `emit_flag()` — a real function in the binary, never normally reachable, that
reads the flag file and writes it straight to the VM's own stdout/socket.

Full write-up: `evals/practice_runs.md` → "Sandworm VM".

## Don't confuse with

- **Classic stack/heap buffer overflow** — this is a bug in the VM interpreter's own bounds
  checking on a *computed index*, not a raw memory-copy overflow (`strcpy`/`memcpy`-style).
- **Type confusion in a scripting-language VM** (e.g. a real language's bytecode interpreter with
  tagged values) — this pattern is about missing bounds validation on an index arithmetic
  expression, not about value-type confusion.
- **ROP/ret2libc** — no stack corruption or return-address control is needed here at all; the
  entire primitive lives inside the VM's own heap-allocated state, and the "gadget" is a real
  named function already in the binary, not an assembled ROP chain.
