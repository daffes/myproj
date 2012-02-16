#-------------------------------------------------------------------------------
# elftools: elf/sectionsedit.py
#
# ELF editable sections
#
# Davi Costa (davialcosta@gmail.com)
# This code is in the public domain
#-------------------------------------------------------------------------------

from ..construct import Container
from ..common.utils import struct_parse
from enums import *

from .sections import (
    StringTableSection, SymbolTableSection, Symbol)

class StringTableSectionEdit(StringTableSection):
    """ ELF editable string table section.
    """
    def __init__(self, elffile, string_table_section=None, name='.strtab'):
        self.marker = "\0\0__%MaRkeR$"
        self.marked = False
        self.control = False
        self.elffile = elffile
        if string_table_section:
            self.header = string_table_section.header
            self.table = string_table_section.data()
            self.name = string_table_section.name
        else:
            self.header = self.build_header()
            self.table = ''
            self.name = name
            
        # Should start with a null char
        if len(self.table) == 0:
            self.table += '\0'

    def get_string(self, offset):
        """ Get the string stored at the given offset in this string table.
        """
        return self.table[offset:self.table.find('\0', offset)]

    def controlled(self):
        self.control = True
        self.marked = False
        off = self.table.find(self.marker+'\0')
        if off == -1:
            off = len(self.table)
        self.table = self.table[0:off]
        return off

    def add_string(self, s):
        off = self.table.find(s+'\0')
        if off == -1:
            if self.control and not self.marked:
                self.table += self.marker + '\0'
                self.marked = True
            off = len(self.table)
            self.table += s + '\0'
        return off

    def data(self):
        return self.table

    def build_header(self):
        return Container(
            sh_name = 0,
            sh_type = 'SHT_STRTAB',
            sh_flags = 0,
            sh_addr = 0,
            sh_offset = 0,
            sh_size = 0,
            sh_link = 0,
            sh_info = 0,
            sh_addralign = 1,
            sh_entsize = 0) # FIX-ME

    def fix_header(self, offset):
        self.header['sh_offset'] = offset
        self.header['sh_size'] = len(self.table)
        return offset + self['sh_size']


class SymbolTableSectionEdit(SymbolTableSection):
    """ ELF symbol table section. Has an associated StringTableSection that's
        passed in the constructor.
    """
    def __init__(self, elffile, symboltable=None, name='.symtab'):
        self.elffile = elffile
        self.elfstructs = self.elffile.structs
        self.symbols = []

        if not symboltable:
            self.header = self.build_header()
            self.name = name
            
            # Create default 0 Entry
            self.symbols.append(SymbolEdit(
                name='\0',
                value=0,
                bind='STB_LOCAL', 
                stype='STT_NOTYPE',
                sname=None,
                size=0,
                visibility='STV_DEFAULT'))

        else:
            self.name = symboltable.name
            self.header = symboltable.header
            if symboltable['sh_size'] > 0:
                for sym in symboltable.iter_symbols():
                    self.symbols.append(SymbolEdit(symbol=sym))

    def add_symbol(self, sym):
        self.symbols.append(sym)

    def push_symbols_names(self, string_table):
        off = string_table.controlled()
        for sym in self.symbols:
            if sym['st_name'] == 0 or sym['st_name'] >= off:
                sym.entry['st_name'] = string_table.add_string(sym.name)
            
    def build_header(self):
        return Container(
            sh_name = 0,
            sh_type = 'SHT_SYMTAB',
            sh_flags = 0,
            sh_addr = 0,
            sh_offset = 0,
            sh_size = 0,
            sh_link = 0,
            sh_info = 0,
            sh_addralign = self.elffile.elfclass/8,
            sh_entsize = self.elfstructs.Elf_Sym.sizeof())
    
    def fix_header(self, offset):
        self.header['sh_offset'] = offset
        
        # sh_entsize is the size of a Symbol
        # This is out of order because will be used next
        self.header['sh_size'] = self['sh_entsize'] * self.num_symbols()
        
        # sh_link should contain the index of the string session
        for i, sec in enumerate(self.elffile.iter_sections()):
            if sec.name == '.strtab':
                self.header['sh_link'] = i
                break
            
        # Put local symbols first
        self.symbols.sort(
            key=lambda sym: \
                0 if sym.entry['st_info']['bind'] == 'STB_LOCAL' \
                else 1)
        
        # sh_info should contain the index of the first
        # non local symbol
        self.header['sh_info'] = 0
        for sym in self.symbols:
            if sym.entry['st_info']['bind'] != 'STB_LOCAL':
                break
            self.header['sh_info'] += 1
        
        return offset + self.header['sh_size']
    
    def num_symbols(self):
        """ Number of symbols in the table
        """
        return len(self.symbols)
        
    def get_symbol(self, n):
        """ Get the symbol at index #n from the table (Symbol object)
        """
        return self.symbols[n]

    def get_symbol_by_name(self, name):
        for sym in self.symbols:
            if sym.name == name:
                return sym

    def remove_symbol(self, n):
        return self.symbols.pop(n)

    def remove_symbol_by_name(self, name):
        for i, sym in enumerate(self.symbols):
            if sym.name == name:
                return self.remove_symbol(i)    

    def data(self):
        # Force creation of the section name to index map
        self.elffile.get_section_by_name('')
        
        d = ''
        for sym in self.symbols:
            sym.install_section(self.elffile._section_name_map)
            d += self.elfstructs.Elf_Sym.build(sym.entry)
        return d

class SymbolEdit(Symbol):
    """ FIX-ME Symbol object - representing a single symbol entry from a symbol table
        section.

        Similarly to Section objects, allows dictionary-like access to the
        symbol entry.
    """
    def __init__(self, name='', value=0, bind='STB_GLOBAL', stype='STT_FUNC', sname='.text', size=0, visibility='STV_DEFAULT', symbol=None):
        if symbol != None:
            self.sname = -1
            self.entry = symbol.entry
            self.name = symbol.name
            return

        self.set_name(name)
        self.entry = self._build_entry()
        self.set_bind(bind)
        self.set_type(stype)
        self.set_visibility(visibility)
        self.set_section(sname)
        self.set_value(value)
        self.set_size(size)
                

    def __str__(self):
        return ('%s: %s\n') % (self.name, self.entry)

    def install_section(self, section_map):
        if self.sname == None:
            self.entry['st_shndx'] = 'SHN_UNDEF'
        elif self.sname != -1:
            self.entry['st_shndx'] = section_map[self.sname]
        
    def set_name(self, name):
        self.name = name

    def get_name(self):
        return self.name

    def set_bind(self, bind):
        assert bind in ENUM_ST_INFO_BIND
        self.entry['st_info']['bind'] = bind
        
    def get_bind(self):
        return self.entry['st_info']['bind']

    def set_type(self, stype):
        assert stype in ENUM_ST_INFO_TYPE
        self.entry['st_info']['type'] = stype

    def get_type(self):
        return self.entry['st_info']['type']

    def set_visibility(self, vis):
        assert vis in ENUM_ST_VISIBILITY
        self.entry['st_other']['visibility'] = vis
    
    def get_visibility(self):
        return self.entry['st_other']['visibility']
    
    def set_section(self, sname):
        self.sname = sname

    def get_section(self):
        return self.sname
        
    def set_value(self, value):
        self.entry['st_value'] = value

    def get_value(self):
        return self.entry['st_value']

    def set_size(self, size):
        self.entry['size'] = size

    def get_size(self):
        return self.entry['size']
        
    def _build_entry(self):
        st_info_container = Container(bind = 'STB_GLOBAL')
        st_info_container.type = 'STT_FUNC'
        return Container(
            st_name = 0,
            st_info = st_info_container,
            st_other = Container(visibility = 'STV_DEFAULT'),
            st_shndx = 'SHN_UNDEF',
            st_value = 0,
            st_size = 0)

