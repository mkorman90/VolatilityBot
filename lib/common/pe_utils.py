import logging
import string
import pefile
import magic
from pefile import PEFormatError

from lib.common.utils import calc_md5, calc_sha256, calc_imphash

IMAGE_NT_OPTIONAL_HDR32_MAGIC = hex(0x10b)
IMAGE_NT_OPTIONAL_HDR64_MAGIC = hex(0x20b)


def static_analysis(sample_dump_instance):
    try:
        pe = pefile.PE(sample_dump_instance.binary_path)
        report = dict()
        report['imports'] = get_imports(pe)
        report['exports'] = get_exports(pe)
        report['general'] = {'md5': calc_md5(sample_dump_instance.binary_path),
                             'sha256': calc_sha256(sample_dump_instance.binary_path),
                             'imphash': calc_imphash(sample_dump_instance.binary_path)}
        report['sections'] = get_section_data(pe)
        report['resources'] = get_resource_data(pe)

        return report
    except PEFormatError as exception:
        logging.error('Could not load PE file: {}'.format(exception))
        return None


def is_64bit(pe):
    # Check PE arch. if 0x10b then
    if hex(pe.OPTIONAL_HEADER.Magic) == IMAGE_NT_OPTIONAL_HDR32_MAGIC:
        return False
    elif hex(pe.OPTIONAL_HEADER.Magic) == IMAGE_NT_OPTIONAL_HDR64_MAGIC:
        return True

    # Could not determine architecture, must be 32bit
    return False


def get_exports(pe):
    """Gets exported symbols.
    @return: exported symbols dict or None.
    """
    exp_list = []

    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for exported_symbol in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exported_symbol.name is not None:
                export_name = exported_symbol.name.decode('utf-8')
            else:
                export_name = 'n/a'

            exp_list.append({
                "address": hex(pe.OPTIONAL_HEADER.ImageBase +
                               exported_symbol.address),
                'name': export_name,
                "ordinal": exported_symbol.ordinal})

    return exp_list


def get_section_data(pe):
    sections = []
    for section in pe.sections:
        section.get_entropy()
        if section.SizeOfRawData == 0 or (
                        section.get_entropy() > 0 and section.get_entropy() < 1) or section.get_entropy() > 7:
            suspicious = True
        else:
            suspicious = False

        scn = section.Name.decode('utf-8')
        md5 = section.get_hash_md5()
        sha1 = section.get_hash_sha1()
        spc = suspicious
        va = hex(section.VirtualAddress)
        vs = hex(section.Misc_VirtualSize)
        srd = section.SizeOfRawData

        is_section_of_ep = False
        if (pe.OPTIONAL_HEADER.AddressOfEntryPoint > section.VirtualAddress) and (
                    pe.OPTIONAL_HEADER.AddressOfEntryPoint < section.VirtualAddress + section.Misc_VirtualSize):
            is_section_of_ep = True

        rwx_flags = {'r': section.IMAGE_SCN_MEM_READ, 'w': section.IMAGE_SCN_MEM_WRITE,
                     'x': section.IMAGE_SCN_MEM_EXECUTE}

        sections.append({"name": scn, "hash_md5": md5, "hash_sha1": sha1, "suspicious": spc, "virtual_address": va,
                         "virtual_size": vs, "size_raw_data": srd, 'section_perm': rwx_flags,
                         'is_section_of_ep': is_section_of_ep, 'entropy': section.get_entropy()})

    if len(sections) > 0:
        return sections
    return None


def get_resource_data(pe):
    resources = []
    if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            resource = {}

            try:
                if resource_type.name is not None:
                    name = str(resource_type.name)
                else:
                    name = str(pefile.RESOURCE_TYPE.get(resource_type.struct.Id))
            except TypeError:
                name = 'unknown'

            if hasattr(resource_type, "directory"):
                for resource_id in resource_type.directory.entries:
                    if hasattr(resource_id, "directory"):
                        for resource_lang in resource_id.directory.entries:
                            data = pe.get_data(resource_lang.data.struct.OffsetToData,
                                               resource_lang.data.struct.Size)
                            language = pefile.LANG.get(resource_lang.data.lang, None)
                            sub_language = pefile.get_sublang_name_for_lang(resource_lang.data.lang,
                                                                            resource_lang.data.sublang)
                            resource["name"] = name
                            resource["offset"] = "0x{0:08x}".format(resource_lang.data.struct.OffsetToData)
                            resource["size"] = "0x{0:08x}".format(resource_lang.data.struct.Size)
                            resource["language"] = language
                            resource["sublanguage"] = sub_language
                            resource['filetype'] = magic.from_buffer(pe.get_memory_mapped_image()[
                                                                     resource_lang.data.struct.OffsetToData:resource_lang.data.struct.OffsetToData + 1024])
                            resources.append(resource)

    return resources


def get_imports(pe):
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        import_list = list()
        for library in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in library.imports:
                try:
                    import_name = imp.name.decode('utf-8')
                except AttributeError:
                    import_name = 'unknown'
                import_list.append({'name': import_name, 'offset': imp.address})
        return import_list
    return None


def fix_pe_from_memory(pe, imagebase=None):
    """
    Fixes PE file from memory and returns the pe
    :param pe: pefile object, assuming valid
    :param imagebase: If we want to change the image base, set it here as int
    :return:
    """

    # Fix image base according
    if imagebase is not None:
        pe.OPTIONAL_HEADER.ImageBase = int(imagebase, 16)

    for section in pe.sections:
        # Change section address back to raw
        logging.info('==' + section.Name.decode('utf-8') + '==')
        logging.info('Modifying virtual addresses:')
        logging.info('{} => {}'.format(hex(section.VirtualAddress), hex(section.PointerToRawData)))
        section.VirtualAddress = section.PointerToRawData
    return pe


def get_strings(sample_dump_instance, imagebase=None, min_length=4):
    """
    Get strings and their relevant offsets. if imagebase was supplied, will calculate form imagebase
    :param sample_dump_instance:
    :param imagebase:
    :param min_length:
    :return:
    """
    string_dict = list()
    current_offset = 0

    if imagebase is None:
        try:
            pe = pefile.PE(sample_dump_instance.binary_path)
            imagebase = pe.OPTIONAL_HEADER.ImageBase
        except PEFormatError:
            imagebase = 0

    with open(sample_dump_instance.binary_path, "rb") as f:
        current_offset += 1
        result = ""
        first_char = True
        offset = None

        for char in f.read():
            if first_char:
                offset = current_offset
                first_char = False

            try:
                if chr(char) in string.printable:
                    result += chr(char)
                    continue
            except TypeError:
                pass

            if len(result) >= min_length:
                if isinstance(imagebase, int):
                    string_dict.append({'string': result, 'offset': hex(imagebase + int(offset))})
                else:
                    string_dict.append({'string': result, 'offset': hex(int(imagebase, 16) + int(offset))})

            result = ""
            first_char = True
            offset = None

    return string_dict
