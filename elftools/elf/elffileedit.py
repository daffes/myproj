#-------------------------------------------------------------------------------
# elftools: elf/elffileedit.py
#
# ELF editable files
#
# Davi Costa (davialcosta@gmail.com)
# This code is in the public domain
#-------------------------------------------------------------------------------

from io import BytesIO
from .elffile import ELFFile
from .sectionsedit import (
    SymbolTableSectionEdit, StringTableSectionEdit, SymbolEdit)
from copy import deepcopy

class ELFFileEdit(ELFFile):
    """ 
    """
    
    def __init__(self, stream):
        # Create a copy of the stream
        stream.seek(0)
        self.stream = BytesIO()
        self.stream.write(stream.read())

        # Call parent constructor
        super(ELFFileEdit, self).__init__(self.stream)
        self._file_stringtable_section.name = self._get_section_name(self._file_stringtable_section.header)
        
        # Control of new and editable sections
        self._new_sections = []
        self._edit_sections = []

        self.stream.seek(0,2)
        self.size = self.stream.tell()
        self._normal = self._check_normal()

        self._load_edit_sections()

        # Set the writting offset 
        # If the file is considered to be "normal" it will be the offset
        # of the shstrtab section, if not it's the end of the file
        if self._normal:
            self.offset = self._shstrtab['sh_offset']
        else:
            self.offset = self.size

    def get_section_name_map(self):
        if self._section_name_map == None:
            self.get_section_by_name('')
        return deepcopy(self._section_name_map)

    def save(self, fname):
        """ Creates a file fname with the updated information """
        # Set the shstrtab offset and get the offset for the section headers
        off = self._shstrtab.fix_header(self.offset)
   
        # align address 
        # not sure if this is needed, but it's like this in most binaries
        k = self.elfclass/8
        off = (off+k-1)/k*k

        # Create a copy and update the elf header
        # Can't self-update because it will break several methods
        eh = self._parse_elf_header()
        eh['e_shnum'] = self.num_sections()
        eh['e_shoff'] = off
        off += eh['e_shnum'] * eh['e_shentsize']

        # Set the symtab offset and get the offset for the strtab
        off = self._symtab.fix_header(off)

        # Push the symbols to string table and update it's header
        self._strtab.fix_header(self._symtab['sh_offset'] 
                               + self._symtab['sh_size'])
        
        # Write the output file
        out = open(fname,"w")

        # Write the elf header
        self.structs.Elf_Ehdr.build_stream(eh, out)

        # copy everything until the section string table 
        self.stream.seek(self['e_ehsize'])
        out.write(self.stream.read(self.offset - self['e_ehsize']))

        # Write the section string table
        out.write(self._shstrtab.data())
        
        # Align address
        while (out.tell()%(self.elfclass/8) != 0):
            out.write('\0')
        
        # Write the sections Headers
        for sec in self.iter_sections():
            self.structs.Elf_Shdr.build_stream(sec.header, out)

        # Finally, write the Symbol and the String table
        out.write(self._symtab.data())
        out.write(self._strtab.data())

        out.close()

    # Symbol editing methods, basically wrappers over 
    # SymbolTableSectionEdit
    def create_symbol(self, name='', value=0, bind='STB_GLOBAL', \
                          stype='STT_FUNC', sname='.text', size=0, \
                          visibility='STV_DEFAULT', add=True):
        """ Creates a new symbol and by default adds it to the symbol table
        Receives: name(''), value(0), bind('STB_GLOBAL'), stype(STT_FUNC),
        sname ('.text'), size,(0) visibility('STV_DEFAULT', add(True)
        Returns a reference to the symbol
        """
        sym = SymbolEdit(name, value, bind, stype, sname, size, visibility)
        if add:
            self.add_symbol(sym)
        return sym

    def add_symbol(self, sym):
        """ Add a sybol object to the table """
        self._symtab.add_symbol(sym)

    def iter_symbols(self):
        """ Iterate over all the symbols of the symbol table """
        return self._symtab.iter_symbols()

    def num_symbols(self):
        """ Get a symbol by it's index """
        return self._symtab.num_symbols()

    def get_symbol(self, n):
        """ Get a symbol by it's index """
        return self._symtab.get_symbol(n)

    def get_symbol_by_name(self, name):
        """ Get a symbol by it's name """
        return self._symtab.get_symbol_by_name(name)

    def remove_symbol(self, n):
        """ Remove a symbol given an index
        indexes after it will be modified """
        return self._symtab.remove_symbol(n)

    def remove_symbol_by_name(self, name):
        """ Remove a symbol given it's name """
        return self._symtab.remove_symbol_by_name(name)

    # Overwrite a few methods to make it consistent
    # with editable and new sections
    def num_sections(self):
        """ Number of sections in the file
        """
        return self['e_shnum'] + len(self._new_sections)
    
    def get_section(self, n):
        """ Get the section at index #n from the file (Section object or a
            subclass)
        """
        if (n < self['e_shnum']):
            section = super(ELFFileEdit,self).get_section(n)
            # Verify if the section is being editted
            for esec in self._edit_sections:
                if esec.name == section.name:
                    section = esec
                    break
        else:
            section = self._new_sections[n - self['e_shnum']]
        return section

    #-------------------------------- PRIVATE --------------------------------#

    def _check_normal(self):
        """ Check if the file is considered to be in the normal format
        A normal format is a file having:
        section string table, sections headers, symbol table, string table
        in this order, without anything between them (except addr alignment)
        and with the string table reaching the end of the file. Symbol table
        and/or string table may be absent.
        """
        # check that shstrtab preceedes section headers
        off = self._file_stringtable_section['sh_offset'] \
            + self._file_stringtable_section['sh_size']
        k = self.elfclass/8
        off = (off+k-1)/k*k 
        if off != self['e_shoff']:
            return False
        off += self['e_shentsize'] * self['e_shnum']

        # Check for anything between section headers and symtab
        symtab = self.get_section_by_name('.symtab')
        if symtab != None:
            if off != symtab['sh_offset']:
                return False
            off += symtab['sh_size']

        # Check for anything between symtab and strtab
        strtab = self.get_section_by_name('.strtab')
        if strtab != None:
            if off != strtab['sh_offset']:
                return False
            off += strtab['sh_size']
        
        # Check for presence of anything else in the end
        # This is the major cause of returning False
        if off != self.size:
            return False
        return True

    def _load_edit_sections(self):
        """ Loads section string table, symbol table, and string table 
        as editable sections. If the two lasts don't exist, create them.
        """
        # Stringtable section (contains sections names), always exists
        # _file_stringtable_section is used to keep consistent with parent class
        self._shstrtab = StringTableSectionEdit(self, self._file_stringtable_section)
        self._file_stringtable_section = self._shstrtab
        self._edit_sections = [self._shstrtab,]

        # Symbol table, load/create
        if self.get_section_by_name('.symtab'):
            self._symtab = SymbolTableSectionEdit(
                self, self.get_section_by_name('.symtab'))           
        else:
            self._symtab = self._add_section(SymbolTableSectionEdit(self))

        # String table, load/create
        if self.get_section_by_name('.strtab'):
            self._strtab = StringTableSectionEdit(
                self, self.get_section_by_name('.strtab'))
        else:
            self._strtab = self._add_section(StringTableSectionEdit(self))

        self._edit_sections.extend([self._strtab, self._symtab, self._strtab])


    def _add_section(self, section):
        """ Add a section object to the file """
        assert self.get_section_by_name(section.name) == None

        # Reset section name mapping
        self._section_name_map = None

        # Add the string in the shstrtab and update the offset in the header
        section.header['sh_name'] = self._shstrtab.add_string(section.name)

        self._new_sections.append(section)
        return section
