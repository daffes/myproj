#-------------------------------------------------------------------------------
# elftools: elf/sectionsedit.py
#
# ELF editable sections
#
# Davi Costa (davialcosta@gmail.com)
# This code is in the public domain
#-------------------------------------------------------------------------------

from io import BytesIO
from .elffile import ELFFile
from .sectionsedit import (
    SymbolTableSectionEdit, StringTableSectionEdit, SymbolEdit)

class ELFFileEdit(ELFFile):
    """ Same as ELFFile but will enforce the existence of two sections:
        .symtab and .strtab
    """
    
    def __init__(self, stream, A=[]):
        stream.seek(0)
        self.stream = BytesIO()
        self.stream.write(stream.read())
        self._new_sections = []
        self._edit_sections = []
        super(ELFFileEdit, self).__init__(self.stream)
        self._file_stringtable_section.name = self._get_section_name(self._file_stringtable_section.header)

        self.stream.seek(0,2)
        self.size = self.stream.tell()

        self._normal = self._check_normal(A)
        self._shstrtab = StringTableSectionEdit(self, self._file_stringtable_section)
        self._file_stringtable_section = self._shstrtab

        self._edit_sections = [self._shstrtab,]
        self._load_edit_sections()

        if self._normal == True:
            self.offset = self._shstrtab['sh_offset']
        else:
            self.offset = self.size

    def _check_normal(self, A=[]):
        # check that shstrtab preceedes section headers
        off = self._file_stringtable_section['sh_offset'] \
            + self._file_stringtable_section['sh_size']
        k = self.elfclass/8
        off = (off+k-1)/k*k # FIX-ME
        if off != self['e_shoff']:
            A[0] = 0
            return False
        off += self['e_shentsize'] * self['e_shnum']

        # Check for anything between section headers and symtab
        symtab = self.get_section_by_name('.symtab')
        if symtab != None:
            if off != symtab['sh_offset']:
                A[0] = 1
                return False
            off += symtab['sh_size']
        
        # Check for anything between symtab and strtab
        strtab = self.get_section_by_name('.strtab')
        if strtab != None:
            if off != strtab['sh_offset']:
                A[0] = 2
                return False
            off += strtab['sh_size']
        
        # Check for anything else in the end
        if off != self.size:
            A[0] = 3
            return False
        return True

    def _load_edit_sections(self):
        if self.get_section_by_name('.symtab'):
            self._symtab = SymbolTableSectionEdit(
                self, self.get_section_by_name('.symtab'))           
        else:
            self._symtab = self._add_section(SymbolTableSectionEdit(self))

        if self.get_section_by_name('.strtab'):
            self._strtab = StringTableSectionEdit(
                self, self.get_section_by_name('.strtab'))
        else:
            self._strtab = self._add_section(StringTableSectionEdit(self))

        self._edit_sections.extend([self._symtab, self._strtab])


    def _add_section(self, section):
        # Invalidate any name mapping
        self._section_name_map = None
        
        # Make sure there isn't a section with the same name
        assert self.get_section_by_name(section.name) == None

        # Add the string in the shstrtab
        section.header['sh_name'] = self._shstrtab.add_string(section.name)

        # Remember the new section
        self._new_sections.append(section)
        self._edit_sections.append(section)
        return section

    def save(self, fname):
        # Update the Headers
        # Update session string table header
        off = self._shstrtab.fix_header(self.offset)
        
        # align address
        k = self.elfclass/8
        off = (off+k-1)/k*k

        # Can't update the self header as it may break
        # iterating in the sections
        eh = self._parse_elf_header()
        eh['e_shnum'] = self.num_sections()
        eh['e_shoff'] = off
        off += eh['e_shnum'] * eh['e_shentsize']

        # Update Symbol Table header
        off = self._symtab.fix_header(off)


        # Push the symbols to string table and update it's header
        self._symtab.push_symbols_names(self._strtab)
        self._strtab.fix_header(self._symtab['sh_offset'] 
                               + self._symtab['sh_size'])

        # Open the output file
        out = open(fname,"w")

        # Write the elf header
        self.structs.Elf_Ehdr.build_stream(eh, out)

        # copy everything until the section string table 
        self.stream.seek(self['e_ehsize'])
        out.write(self.stream.read(self.offset - self['e_ehsize']))

        # Write the section string table
        out.write(self._shstrtab.data())
        while (out.tell()%(self.elfclass/8) != 0):
            out.write('\0')
        
        # Write the sections Headers replacing editable ones
        for sec in self.iter_sections():
            self.structs.Elf_Shdr.build_stream(sec.header, out)

        # Finally write the Symbol and the String table
        out.write(self._symtab.data())
        out.write(self._strtab.data())
        out.close()

    # Symbol editing methods, basically wrappers over 
    # SymbolTableSectionEdit
    def create_symbol(self, name='', value=0, bind='STB_GLOBAL', stype='STT_FUNC', sname='.text', size=0, visibility='STV_DEFAULT', add=True):
        sym = SymbolEdit(name, value, bind, stype, sname, size, visibility)
        if add:
            self.add_symbol(sym)
        return sym

    def add_symbol(self, sym):
        self._symtab.add_symbol(sym)

    def iter_symbols(self):
        return self._symtab.iter_symbols()

    def get_symbol(self, n):
        return self._symtab.get_symbol(n)

    def get_symbol_by_name(self, name):
        return self._symtab.get_symbol_by_name(name)

    def remove_symbol(self, n):
        return self._symtab.remove_symbol(n)

    def remove_symbol_by_name(self, name):
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
            for esec in self._edit_sections:
                if esec.name == section.name:
                    section = esec
                    break
        else:
            section = self._new_sections[n - self['e_shnum']]
        return section
