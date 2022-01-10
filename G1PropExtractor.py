# coding: utf-8
import ida_name
import ida_segment
import idautils
import idaapi
import struct
import idc
import json


class PrepareGlacierPropertiesTableAction(idaapi.action_handler_t):
    def __init__(self,
                 add_trivial_property_comments=False,
                 rename_property_table_entry_points=False):
        idaapi.action_handler_t.__init__(self)
        self._add_trivial_property_comments = add_trivial_property_comments
        self._rename_property_table_entry_pointer = rename_property_table_entry_points

    def activate(self, context):
        ea = idc.get_screen_ea()
        print("Start lookup at {:08X}".format(ea))

        mnemonic = idaapi.ua_mnem(ea)
        if not mnemonic == 'mov':
            print(" Failed to perform analysis! You should put cursor on mov instruction!")
            return

        class_properties_address = idc.get_operand_value(ea, 1)
        current_function_name = idc.get_func_name(ea)
        demangled_current_function_name = idc.demangle_name(current_function_name, idc.get_inf_attr(idc.INF_SHORT_DN))

        class_properties_provider_function_name = current_function_name if demangled_current_function_name is None else demangled_current_function_name
        if class_properties_provider_function_name is None or class_properties_provider_function_name == 'None':
            print("Failed to perform analysis: unable to recognize name of current function. "
                  "Make sure that you put your cursor inside GetProperties function!")
            return

        if '::' not in class_properties_provider_function_name:
            print("WARNING: Your class name will not be recognized because your function does not contains class name!")

        class_name_org = class_properties_provider_function_name.split('::')[0] if '::' in class_properties_provider_function_name else class_properties_provider_function_name
        class_properties, class_parents, class_name = self.prepare_class_properties(class_properties_address)

        result = {
            'class_name': class_name_org,
            'properties': class_properties,
            'parent': class_parents
        }

        if self._rename_property_table_entry_pointer and idc.get_func_name(ea).startswith("sub_"):
            idc.set_name(ea, "{}::GetProperties".format(class_name), ida_name.SN_PUBLIC)

        if self._add_trivial_property_comments:
            idc.set_cmt(ea, '{}::Info'.format(class_name_org), 0)

        print("RESULT: ")
        print(json.dumps(result))

    def prepare_class_properties(self, header_address):
        first_property_address = struct.unpack('<i', idc.get_bytes(header_address, 4))[0]
        first_parent_address = struct.unpack('<i', idc.get_bytes(header_address + 4, 4))[0]
        name_address = struct.unpack('<i', idc.get_bytes(header_address + 0x8, 0x4))[0]

        idc.create_dword(header_address)
        idc.create_dword(header_address + 0x4)
        idc.create_dword(header_address + 0x8)

        class_name = None

        if self._rename_property_table_entry_pointer:
            xrefs_to_symbol = [xref.frm for xref in idautils.XrefsTo(header_address) if
                               xref.to == header_address and ida_segment.getseg(
                                   xref.frm).sclass == ida_segment.SEG_CODE]
            if len(xrefs_to_symbol) == 0:
                print("Unable to recognize name of symbol at {:08X}".format(header_address))
            else:
                xrefs_to_function = [xref.frm for xref in idautils.XrefsTo(xrefs_to_symbol[0]) if
                                     idc.get_segm_name(xref.frm).lower() == ".rdata"]
                if len(xrefs_to_function) == 0:
                    print("Unable to recognize pointer of vftable to function at {:08X} for symbol at {:08X}".format(
                        xrefs_to_symbol[0], header_address))
                else:
                    # Here we need to find root of vtbl
                    vtbl_root_found = False
                    vtbl_sp = xrefs_to_function[0]
                    vtbl_addr = vtbl_sp

                    vtbl_is_fp = True
                    while vtbl_is_fp:
                        vtbl_addr -= 0x4
                        vtbl_fp = struct.unpack('<i', idc.get_bytes(vtbl_addr, 0x4))[0]
                        if idc.get_segm_name(vtbl_fp).lower() == ".rdata":
                            vtbl_root_found = True
                            vtbl_is_fp = False

                    if not vtbl_root_found:
                        print("Too big vtbl for method at {:08X} for symbol at {:08X}".format(xrefs_to_function[0],
                                                                                              header_address))
                    else:
                        """ 
                            NOTE: Here we should unroll RTTI internals but it's a little buggy
                            Original code (fix later or never)

                            rtti_addr = struct.unpack('<i', idc.get_bytes(vtbl_addr, 0x4))[0]
                            rtti_description_addr = struct.unpack('<i', idc.get_bytes(rtti_addr + 0xC, 0x4))[0]
                            rtti_type_name = idc.get_strlit_contents(rtti_description_addr + 0x8).decode('ascii')

                            here we unable to demangle value of rtti_type_name. Really don't know why
                            I will do same thing easier
                        """
                        # Take off 0x10
                        rtti_type_name = idc.generate_disasm_line(vtbl_addr, 0)
                        try:
                            rtti_type_name = rtti_type_name[
                                             rtti_type_name.index('; const ') + 8: rtti_type_name.index('::`')]
                        except ValueError as ve:
                            print("ValueError: Failed to prepare name {} at vtbl {:08X} origin {:08X}".format(rtti_type_name, vtbl_addr, xrefs_to_function[0]))
                            raise ve

                        class_name = rtti_type_name
                        idc.set_name(header_address, '{}::Info'.format(rtti_type_name), ida_name.SN_PUBLIC)

        properties = []
        parents = []
        name = None

        if not name_address == 0x0:
            name = idc.get_strlit_contents(name_address).decode('ascii')
        else:
            name = None

        if not first_property_address == 0x0:
            properties = self.prepare_properties_recursive(first_property_address, class_name)
        else:
            properties = None

        if not first_parent_address == 0x0:
            parents = self.prepare_class_properties(first_parent_address)
        else:
            parents = None

        return properties, parents, name if name is not None else class_name

    def prepare_properties_recursive(self, property_address, class_name):
        result = []
        next_property_address = struct.unpack('<i', idc.get_bytes(property_address, 0x4))[0]
        flag0 = struct.unpack('<i', idc.get_bytes(property_address + 0x4, 0x4))[0]
        flag1 = struct.unpack('<i', idc.get_bytes(property_address + 0x8, 0x4))[0]
        loader_function_vtable_address = struct.unpack('<i', idc.get_bytes(property_address + 0xC, 0x4))[0]

        idc.create_dword(property_address + 0x0)
        idc.create_dword(property_address + 0x4)
        idc.create_dword(property_address + 0x8)
        idc.create_dword(property_address + 0xC)

        possible_pointer_or_offset = struct.unpack('<i', idc.get_bytes(property_address + 0x10, 0x4))[0]
        if not possible_pointer_or_offset == 0x0:
            idc.create_dword(property_address + 0x10)
            # It's trivial type
            type_obj = {'type': 'Trivial', 'offset': possible_pointer_or_offset,
                        'address': '{:08X}'.format(property_address),
                        'name': str('{}::Property_{:X}'.format(class_name, possible_pointer_or_offset))}

            if self._rename_property_table_entry_pointer:
                idc.set_name(property_address, type_obj['name'], idc.SN_PUBLIC)

            result.append(type_obj)
        else:
            idc.create_dword(property_address + 0x10)
            idc.create_dword(property_address + 0x14)
            idc.create_dword(property_address + 0x18)
            idc.create_dword(property_address + 0x1C)
            idc.create_dword(property_address + 0x20)

            # # It's enum or field
            last_entry = struct.unpack('<i', idc.get_bytes(property_address + 0x20, 0x4))[0]
            is_enum = False

            # To recognize is this entry enum or not
            # we need to lookup at last_entry + 0x4 and if there placed valid string it is enum
            is_enum = idc.get_strlit_contents(struct.unpack('<i', idc.get_bytes(last_entry + 0x4, 0x4))[0]) is not None

            if not is_enum:   # BUG: We need to more correct way to recognize enum or struct field
                # It's custom serializable property
                type_obj = {
                    'type': 'Field',
                    'address': '{:08X}'.format(property_address),
                    'loader_fn': '{:08X}'.format(loader_function_vtable_address),
                    'getter': '{:08X}'.format(property_address + 0x10),
                    'setter': '{:08X}'.format(property_address + 0x18)
                }

                result.append(type_obj)
            else:
                # It's enum based property
                enum_info = self.extract_enum_info(last_entry)
                type_obj = {
                    'type': 'Enum',
                    'name': enum_info['name'],
                    'data': enum_info,
                    'address': '{:08X}'.format(property_address)
                }

                result.append(type_obj)

        if not next_property_address == 0x0:
            result += self.prepare_properties_recursive(next_property_address, class_name)

        return result

    def extract_enum_info(self, enum_address):
        enum_info = {'name': '???', 'entries': [], 'address': '{:08X}'.format(enum_address)}
        next_entry = struct.unpack('<i', idc.get_bytes(enum_address, 0x4))[0]
        enum_name_address = struct.unpack('<i', idc.get_bytes(enum_address + 0x4, 0x4))[0]
        enum_info['name'] = idc.get_strlit_contents(enum_name_address).decode('ascii')
        enum_info['entries'] = self.extract_enum_entries_recursive(next_entry)
        return enum_info

    def extract_enum_entries_recursive(self, enum_entry_address):
        result = []
        next_entry = struct.unpack('<i', idc.get_bytes(enum_entry_address, 0x4))[0]
        entry_value = struct.unpack('<i', idc.get_bytes(enum_entry_address + 0x4, 0x4))[0]
        entry_name_address = struct.unpack('<i', idc.get_bytes(enum_entry_address + 0x8, 0x4))[0]
        entry_name = idc.get_strlit_contents(entry_name_address).decode('ascii')
        result.append({'name': str(entry_name), 'value': entry_value})

        if not next_entry == 0x0:
            result += self.extract_enum_entries_recursive(next_entry)

        return result

    def update(self, context):
        return idaapi.AST_ENABLE_ALWAYS


class PluginUtils:
    PLUGIN_PATH = 'Edit/Plugins/Glacier Tools'
    PLUGIN_MENU_ENTRY_INSTERT_AFTER = PLUGIN_PATH
    PLUGIN_ACTIONS = [
        ('ReGlacier:ExtractProperties', '[G1] Extract properties', PrepareGlacierPropertiesTableAction(False, False)),
        ('ReGlacier:ExtractPropertiesAndRenameEntryPoints', '[G1] Extract properties & rename entry points', PrepareGlacierPropertiesTableAction(True, True))
    ]

    @staticmethod
    def unregister_actions():
        # Unregister previous action
        for action_id, _action_name, _action_impl in PluginUtils.PLUGIN_ACTIONS:
            idaapi.detach_action_from_menu(PluginUtils.PLUGIN_PATH, action_id)
            idaapi.unregister_action(action_id)

    @staticmethod
    def register_actions():
        for action_id, action_name, action_impl in PluginUtils.PLUGIN_ACTIONS:
            action_description = idaapi.action_desc_t(action_id, action_name, action_impl)
            idaapi.register_action(action_description)
            idaapi.attach_action_to_menu(PluginUtils.PLUGIN_MENU_ENTRY_INSTERT_AFTER, action_id, idaapi.SETMENU_APP)


def main():
    PluginUtils.unregister_actions()
    PluginUtils.register_actions()
    print(" *** G1PropExtractor.py plugin registered! *** ")


if __name__ == "__main__":
    main()
