#!/usr/bin/env python
from argparse import ArgumentParser
from functools import lru_cache
from sys import argv
from typing import NamedTuple

from bitstring import BitArray, Bits
from coinflip.collections import FloorDict
from more_itertools import sliced

__all__ = ["literal", "repeat", "make_gzip_quine"]


@lru_cache()
def literal(n, final=False):
    len_code = Bits(uintle=n, length=16)

    b = concat_bits(
        Bits(uint=0 if not final else 1, length=1),
        Bits(uint=0, length=2),
        Bits(uint=0, length=5),
        len_code,
        ~len_code,
    )

    return b


class Symbol(NamedTuple):
    code: int
    lenbase: int
    nbits: int


lengths = FloorDict({
    3: Symbol(257, 3, 0),
    4: Symbol(258, 4, 0),
    5: Symbol(259, 5, 0),
    6: Symbol(260, 6, 0),
    7: Symbol(261, 7, 0),
    8: Symbol(262, 8, 0),
    9: Symbol(263, 9, 0),
    10: Symbol(264, 10, 0),
    11: Symbol(265, 11, 1),
    13: Symbol(266, 13, 1),
    15: Symbol(267, 15, 1),
    17: Symbol(268, 17, 1),
    19: Symbol(269, 19, 2),
    23: Symbol(270, 23, 2),
    27: Symbol(271, 27, 2),
    31: Symbol(272, 31, 2),
    35: Symbol(273, 35, 3),
    43: Symbol(274, 43, 3),
    51: Symbol(275, 51, 3),
    59: Symbol(276, 59, 3),
    67: Symbol(277, 67, 4),
    83: Symbol(278, 83, 4),
    99: Symbol(279, 99, 4),
    115: Symbol(280, 115, 4),
    131: Symbol(281, 131, 5),
    163: Symbol(282, 163, 5),
    195: Symbol(283, 195, 5),
    227: Symbol(284, 227, 5),
    258: Symbol(285, 258, 0),
})


distances = FloorDict({
    1: Symbol(0, 1, 0),
    2: Symbol(1, 2, 0),
    3: Symbol(2, 3, 0),
    4: Symbol(3, 4, 0),
    5: Symbol(4, 5, 1),
    7: Symbol(5, 7, 1),
    9: Symbol(6, 9, 2),
    13: Symbol(7, 13, 2),
    17: Symbol(8, 17, 3),
    25: Symbol(9, 25, 3),
    33: Symbol(10, 33, 4),
    49: Symbol(11, 49, 4),
    65: Symbol(12, 65, 5),
    97: Symbol(13, 97, 5),
    129: Symbol(14, 129, 6),
    193: Symbol(15, 193, 6),
    257: Symbol(16, 257, 7),
    385: Symbol(17, 385, 7),
    513: Symbol(18, 513, 8),
    769: Symbol(19, 769, 8),
    1025: Symbol(20, 1025, 9),
    1537: Symbol(21, 1537, 9),
    2049: Symbol(22, 2049, 10),
    3073: Symbol(23, 3073, 10),
    4097: Symbol(24, 4097, 11),
    6145: Symbol(25, 6145, 11),
    8193: Symbol(26, 8193, 12),
    12289: Symbol(27, 12289, 12),
    16385: Symbol(28, 16385, 13),
    24577: Symbol(29, 24577, 13),
})


@lru_cache()
def repeat(n, final=False):
    if n >= 67:
        raise ValueError(f"repeat command can't be 5 bytes long when n is {n}, use n < 67")

    bfinal = Bits(uint=0 if not final else 1, length=1)
    btype = Bits(uint=1, length=2)  # compressed using fixed Huffman codes

    dist_sym = distances[n]
    dist_code = Bits(uint=dist_sym.code, length=5)
    if dist_sym.nbits:
        dist_code += Bits(uint=n - dist_sym.lenbase, length=dist_sym.nbits)[::-1]

    x = n // 2
    y = n - x

    x_sym = lengths[x]
    x_len_code = Bits(uint=x_sym.code - 256, length=7)
    if x_sym.nbits:
        x_len_code = x_len_code + Bits(uint=x - x_sym.lenbase, length=x_sym.nbits)[::-1]

    y_sym = lengths[y]
    y_len_code = Bits(uint=y_sym.code - 256, length=7)
    if y_sym.nbits:
        y_len_code = y_len_code + Bits(uint=y - y_sym.lenbase, length=y_sym.nbits)[::-1]

    b = concat_bits(
        bfinal,
        btype[::-1],
        x_len_code,
        dist_code,
        y_len_code,
        dist_code,
    )

    bits_left = 5 * 8 - len(b)
    if bits_left > 0:
        pad = Bits([0 for _ in range(bits_left)])
        b.append(pad)

    b[:] = sum([byte[::-1] for byte in sliced(b, 8)])

    return b


def make_gzip_quine(fname: str):
    header = concat_bits(
        Bits("0x 1f 8b"),          # magic number
        Bits(uint=8, length=8),    # compression method = deflate
        Bits("0b 0000 1000"),      # flags = [fname]
        Bits(uint=0, length=32),   # modified time = no timestamp available
        Bits("0b 0000 0000"),      # extra flags = []
        Bits(uint=255, length=8),  # operating system = unknown
        Bits(fname.encode()),         # fname = quine.gz
        Bits(uint=0, length=8),    # terminate fname
    )

    crc = 0
    isize = 0
    trailer = concat_bits(
        Bits(uint=crc, length=32),
        Bits(uint=isize, length=32),
    )

    header_nbytes = len(header.bytes)
    trailer_nbytes = len(trailer.bytes)

    data = concat_bits(
        literal(header_nbytes + 5),
        header,
        literal(header_nbytes + 5),

        repeat(header_nbytes + 5),

        literal(5),
        repeat(header_nbytes + 5),

        literal(5),
        literal(5),

        literal(20),
        repeat(header_nbytes + 5),
        literal(5),
        literal(5),
        literal(20),

        repeat(20),

        literal(20),
        repeat(20),
        literal(20),
        repeat(20),
        literal(20),

        repeat(20),

        literal(20),
        repeat(20),
        literal(0),
        literal(0),
        literal(trailer_nbytes + 5),

        repeat(20),

        literal(0),

        literal(0),

        literal(trailer_nbytes + 5),
        repeat(trailer_nbytes + 5),
        trailer,

        repeat(trailer_nbytes + 5),
    )

    b = concat_bits(
        header,
        data,
        trailer,
    )

    return b.bytes


def concat_bits(*bits):
    merged_bits = sum(bits)
    barray = BitArray(merged_bits)

    return barray


def main():
    parser = ArgumentParser()
    parser.add_argument("out")
    args = parser.parse_args(argv[1:])

    quine = make_gzip_quine(args.out)
    binary = bytes(quine)

    with open(args.out, "wb") as f:
        f.write(binary)


if __name__ == "__main__":
    main()
