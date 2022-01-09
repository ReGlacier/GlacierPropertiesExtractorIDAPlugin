# coding: utf-8
import ida_bytes
import ida_enum
import ida_name
import idaapi
import struct
import idc
import json


class PrepareGlacierPropertiesTableAction(idaapi.action_handler_t):
    def __init__(self,
                 auto_register_enumerations=False,
                 add_trivial_property_comments=False,
                 rename_property_table_entry_points=False):
        idaapi.action_handler_t.__init__(self)
        self._auto_register_enumerations = auto_register_enumerations
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
        class_properties, class_parents, class_name = self.prepare_class_properties(class_properties_address, class_name_org)

        result = {
            'class_name': class_name_org,
            'properties': class_properties,
            'parent': class_parents
        }

        if self._add_trivial_property_comments:
            idc.set_cmt(ea, '{}::Info'.format(class_name_org), 0)

        print("RESULT: ")
        print(json.dumps(result))

    def prepare_class_properties(self, header_address, ext_class_name):
        first_property_address = struct.unpack('<i', idc.get_bytes(header_address, 4))[0]
        first_parent_address = struct.unpack('<i', idc.get_bytes(header_address + 4, 4))[0]
        name_address = struct.unpack('<i', idc.get_bytes(header_address + 0x8, 0x4))[0]

        properties = []
        parents = []
        name = None

        if not name_address == 0x0:
            name = idc.get_strlit_contents(name_address).decode('ascii')
        else:
            name = None

        if not first_property_address == 0x0:
            properties = self.prepare_properties_recursive(first_property_address, ext_class_name if name is None else name)
        else:
            properties = None

        if not first_parent_address == 0x0:
            parents = self.prepare_class_properties(first_parent_address, ext_class_name if name is None else name)
        else:
            parents = None

        if self._rename_property_table_entry_pointer:
            current_name = idc.get_name(header_address)
            if current_name.startswith('unk_') or current_name.startswith('dword_'):
                idc.set_name(header_address, '{}::Info'.format(ext_class_name if name is None else name), ida_name.SN_PUBLIC)
                idc.create_dword(header_address)
                idc.create_dword(header_address + 0x4)
                idc.create_dword(header_address + 0x8)

        return properties, parents, name

    def prepare_properties_recursive(self, property_address, class_name):
        result = []
        next_property_address = struct.unpack('<i', idc.get_bytes(property_address, 0x4))[0]
        flag0 = struct.unpack('<i', idc.get_bytes(property_address + 0x4, 0x4))[0]
        flag1 = struct.unpack('<i', idc.get_bytes(property_address + 0x8, 0x4))[0]
        loader_function_vtable_address = struct.unpack('<i', idc.get_bytes(property_address + 0xC, 0x4))[0]
        ida_name = None

        if idc.hasUserName(property_address):
            ida_name = idc.get_name(property_address)

        possible_pointer_or_offset = struct.unpack('<i', idc.get_bytes(property_address + 0x10, 0x4))[0]
        if not possible_pointer_or_offset == 0x0:
            # It's trivial type
            type_obj = {
                'type': 'Trivial',
                'offset': possible_pointer_or_offset,
                'address': '{:08X}'.format(property_address)
            }

            if ida_name is not None:
                type_obj['name'] = ida_name
            else:
                new_name = '{}::Property_{:X}'.format(class_name, possible_pointer_or_offset)
                type_obj['name'] = new_name
                idc.set_name(property_address, new_name, idc.SN_PUBLIC)

            result.append(type_obj)
        else:
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
                    'loader_fn': loader_function_vtable_address,
                    'getter': '{:08X}'.format(property_address + 0x10),
                    'setter': '{:08X}'.format(property_address + 0x18)
                }

                if ida_name is not None:
                    type_obj['name'] = ida_name
                else:
                    #TODO: Implement name extraction of recognized loaders?
                    pass

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

                if self._auto_register_enumerations and len(enum_info['entries']) > 0:
                    enum_name = '{}::{}'.format(class_name, enum_info['name'])
                    enum_id = ida_enum.add_enum(idc.BADADDR, enum_name, 0)
                    for entry in enum_info['entries']:
                        ida_enum.add_enum_member(enum_id, entry['name'], entry['value'], ida_enum.DEFMASK)
                    print("Registered enum {}".format(enum_name))

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
        result.append({'name': entry_name, 'value': entry_value})

        if not next_entry == 0x0:
            result += self.extract_enum_entries_recursive(next_entry)

        return result

    def update(self, context):
        return idaapi.AST_ENABLE_ALWAYS


class PluginUtils:
    PLUGIN_PATH = 'Edit/Plugins/Glacier Tools'
    PLUGIN_MENU_ENTRY_INSTERT_AFTER = PLUGIN_PATH
    PLUGIN_ACTIONS = [
        ('ReGlacier:ExtractProperties', '[G1] Extract properties', PrepareGlacierPropertiesTableAction(False, False, False)),
        ('ReGlacier:ExtractPropertiesAndMarkEnumerations', '[G1] Extract properties & mark enumerations', PrepareGlacierPropertiesTableAction(True, False, False)),
        ('ReGlacier:ExtractPropertiesMarkEnumerationsAndRenameEntryPoints', '[G1] Extract properties & mark enumerations & rename entry points', PrepareGlacierPropertiesTableAction(True, True, True))
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
