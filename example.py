from elftools.elf.elffile import NormELFFile
import sys

f = NormELFFile(open(sys.argv[1]))
f.symtab.add_symbol('f', 0x080483b4) 
f.symtab.add_symbol('main', 0x080483c8)
f.save(sys.argv[2])

