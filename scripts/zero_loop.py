"""Recognize one exact, synthetic-assembler-verified bounded zero-fill primitive."""
# str x0,[x1],#8; subs x2,x2,#1; b.ne back-two-instructions
PATTERN = bytes.fromhex('208400f8420400f1c1ffff54')


def recognize(code, registers, pc, base, size):
    if code != PATTERN or registers[0] != 0:
        return None
    pointer, count = registers[1], registers[2]
    if pointer % 8 or not 1 <= count <= 8192:
        return None
    end = pointer + count*8
    if not base <= pointer < end <= base+size or end >= 1 << 64:
        return None
    # These are precisely the architectural effects of the verified loop.
    return dict(address=pointer, bytes=count*8, x1=end, x2=0, pc=pc+12, nzcv=6,
                emulated_instructions=3*count)
