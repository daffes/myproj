# gcc simple.c -o simple
# strip simple
# python example.py simple out (can't change inplace for now)
# gdb out
#    break main
#    break f
#    run
#    step until the end...
# The two addresses are hardcoded based on a 32bits compilation
# You may need to fix those addresses by those found
# in the command "readelf -s simple" before stripping the file

from elftools.elf.elffile import NormELFFile
import sys

f = NormELFFile(open(sys.argv[1]))
f.symtab.add_symbol('f', 0x080483b4) 
f.symtab.add_symbol('main', 0x080483c8)
f.save(sys.argv[2])

