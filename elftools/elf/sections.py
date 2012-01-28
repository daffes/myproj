#-------------------------------------------------------------------------------
# elftools: elf/sections.py
#
# ELF sections
#
# Eli Bendersky (eliben@gmail.com)
# This code is in the public domain
#-------------------------------------------------------------------------------
from ..construct import CString
from ..common.utils import struct_parse, elf_assert
from ..construct import Container
from enums import *
import copy

class Section(object):
    """ Base class for ELF sections. Also used for all sections types that have
        no special functionality.
        
        Allows dictionary-like access to the section header. For example:
         > sec = Section(...)
         > sec['sh_type']  # section type
    """
    def __init__(self, header, name, stream):
        self.header = header
        self.name = name
        self.stream = stream
    
    def data(self):
        """ The section data from the file.
        """
        self.stream.seek(self['sh_offset'])
        return self.stream.read(self['sh_size'])

    def is_null(self):
        """ Is this a null section?
        """
        return False
        
    def __getitem__(self, name):
        """ Implement dict-like access to header entries
        """
        return self.header[name]

    def __eq__(self, other):
        return self.header == other.header


class NullSection(Section):
    """ ELF NULL section
    """
    def __init__(self, header, name, stream):
        super(NullSection, self).__init__(header, name, stream)

    def is_null(self):
        return True
        

class StringTableSection(Section):
    """ ELF string table section.
    """
    def __init__(self, header, name, stream):
        super(StringTableSection, self).__init__(header, name, stream)
        
    def get_string(self, offset):
        """ Get the string stored at the given offset in this string table.
        """
        table_offset = self['sh_offset']
        return struct_parse(
            CString(''),
            self.stream,
            stream_pos=table_offset + offset)

class StringTableSectionEdit(StringTableSection):
    """ ELF editable string table section.
    """
    def __init__(self, string_table_section):
        self.header = string_table_section.header
        self.table = string_table_section.data()

        # Should start with a null char
        if len(self.table) == 0:
            self.table += '\0'
        
    def get_string(self, offset):
        """ Get the string stored at the given offset in this string table.
        """
        return self.table[offset:self.table.find('\0', offset)]

    def add_string(self, s):
        offset = len(self.table)
        self.table += s + '\0'
        return offset

    def data(self):
        return self.table

    def fix_header(self, offset):
        self.header['sh_offset'] = offset
        self.header['sh_size'] = len(self.table)
        
class SymbolTableSection(Section):
    """ ELF symbol table section. Has an associated StringTableSection that's
        passed in the constructor.
    """
    def __init__(self, header, name, stream, elffile, stringtable):
        super(SymbolTableSection, self).__init__(header, name, stream)
        self.elffile = elffile
        self.elfstructs = self.elffile.structs
        self.stringtable = stringtable
        #elf_assert(self['sh_entsize'] > 0,
        #        'Expected entry size of section %s to be > 0' % name)
        #elf_assert(self['sh_size'] % self['sh_entsize'] == 0,
        #        'Expected section size to be a multiple of entry size in section %s' % name)

    def num_symbols(self):
        """ Number of symbols in the table
        """
        return self['sh_size'] // self['sh_entsize']
        
    def get_symbol(self, n):
        """ Get the symbol at index #n from the table (Symbol object)
        """
        # Grab the symbol's entry from the stream
        entry_offset = self['sh_offset'] + n * self['sh_entsize']
        entry = struct_parse(
            self.elfstructs.Elf_Sym,
            self.stream,
            stream_pos=entry_offset)
        # Find the symbol name in the associated string table
        name = self.stringtable.get_string(entry['st_name'])
        return Symbol(entry, name)

    def iter_symbols(self):
        """ Yield all the symbols in the table
        """
        for i in range(self.num_symbols()):
            yield self.get_symbol(i)


class SymbolTableSectionEdit(SymbolTableSection):
    """ ELF symbol table section. Has an associated StringTableSection that's
        passed in the constructor.
    """
    def __init__(self, symboltable):
        self.elffile = symboltable.elffile
        self.elfstructs = self.elffile.structs

        self.symbols = []
        self.header = symboltable.header
        if symboltable['sh_size'] > 0:
            for sym in symboltable.iter_symbols():
                self.symbols.append(sym)
        else:
            # Create default 0 Entry
            st_info_container = Container(
                bind = 'STB_LOCAL'
                )
            st_info_container.type = 'STT_NOTYPE'
            
            entry = Container(
                st_name = 0,
                st_info = st_info_container,
                st_other = Container(visibility = 'STV_DEFAULT'),
                st_shndx = 'SHN_UNDEF',
                st_value = 0,
                st_size = 0 # FIX-ME
                )
            self.symbols.append(Symbol(entry, ''))

        #elf_assert(self['sh_entsize'] > 0,
        #        'Expected entry size of section %s to be > 0' % name)
        #elf_assert(self['sh_size'] % self['sh_entsize'] == 0,
        #        'Expected section size to be a multiple of entry size in section %s' % name)
    def add_symbol(self, name, value):
        # HACK for 'type' reserved name
        st_info_container = Container(
            bind = 'STB_GLOBAL'
            )
        st_info_container.type = 'STT_FUNC'

        entry = Container(
            st_name = -1,
            st_info = st_info_container,
            st_other = Container(visibility = 'STV_DEFAULT'),
            st_shndx = -1,
            st_value = value,
            st_size = 0 # FIX-ME
            )
        
        self.symbols.append(Symbol(entry, name))
        
    def push_symbols_names(self, string_table):
        for i, sec in enumerate(self.elffile.iter_sections()):
            if sec.name == '.text':
                text_index = i
                break
        
        for sym in self.symbols:
            if sym['st_name'] == -1:
                sym.entry['st_name'] = string_table.add_string(sym.name)
            if sym['st_shndx'] == -1:
                sym.entry['st_shndx'] = text_index
            
    def fix_header(self, offset):
        self.header['sh_type'] = 'SHT_SYMTAB'
        self.header['sh_offset'] = offset

        # sh_entsize Is the size of a Symbol
        # This is out of order because will be used next
        self.header['sh_entsize'] = self.elfstructs.Elf_Sym.sizeof()

        self.header['sh_size'] = self['sh_entsize'] * self.num_symbols()
        
        # sh_link should contain the index of the string session
        for i, sec in enumerate(self.elffile.iter_sections()):
            if sec.name == '.strtab':
                self.header['sh_link'] = i
                break

        # sh_info should contain the index of the first
        # non local symbol
        self.header['sh_info'] = 0
        for sym in self.symbols:
            if sym.entry['st_info']['bind'] != 'STB_LOCAL':
                break
            self.header['sh_info'] += 1
        
        # addralign I don't really know, but I guess it's the number
        # of bytes for each field FIX-ME
        for subcon in self.elfstructs.Elf_Shdr.subcons:
            if subcon.name == 'sh_addralign':
                self.header['sh_addralign'] = subcon.sizeof()        
                            
    
    def num_symbols(self):
        """ Number of symbols in the table
        """
        return len(self.symbols)
        
    def get_symbol(self, n):
        """ Get the symbol at index #n from the table (Symbol object)
        """
        return self.symbols[n]

    def data(self):
        d = ''
        for sym in self.symbols:
            d += self.elfstructs.Elf_Sym.build(sym.entry)
        return d

class Symbol(object):
    """ Symbol object - representing a single symbol entry from a symbol table
        section.

        Similarly to Section objects, allows dictionary-like access to the
        symbol entry.
    """
    def __init__(self, entry, name):
        self.entry = entry
        self.name = name

    def __getitem__(self, name):
        """ Implement dict-like access to entries
        """
        return self.entry[name]


