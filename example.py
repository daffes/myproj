# gcc simple.c -o simple
# strip simple
# python example.py simple out (can't change inplace for now)
# gdb out
#    break main
#    break f
#    run
#    step until the end...

from elftools.elf.elffile import NormELFFile
import sys

f = NormELFFile(open(sys.argv[1]))
f.symtab.add_symbol('f', 0x4004f4)
f.symtab.add_symbol('main', 0x400504)
f.save(sys.argv[2])

