from Registry import Registry

class registry(object):

    def __init__(self):
        self.distinct_items = []

    def get_distinct_items(self, items):
        # Gets distinct list of items from matched objects list
        if self.distinct_items:
            return self.distinct_items

        for item in items:
            self.fill_distinct_list(item)

        return self.distinct_items

    def _isduplicate(self, new_value, values):
        for _v in values:
            if _v.name() == new_value.name():
                return True
        return False

    def fill_distinct_list(self, new_item):

        pattern_new_item = f"{new_item['hive'].file_path}\{new_item['key'].path()}"
        duplicate = None

        for item in self.distinct_items:
            hive = item["hive"].file_path
            key = item["key"].path()
            pattern_item = f"{hive}\{key}"

            if not isinstance(new_item["values"], list):
                new_item["values"] = [new_item["values"]]

            # Case same hive and same key path
            if pattern_item == pattern_new_item:
                # Extend values if applicable
                for new_val in new_item["values"]:
                    duplicate = self._isduplicate(new_val, item["values"])
                    if duplicate:
                        continue
                    else:
                        (item["values"]).append(new_val)

        # Case when no pattern found in matched objects AKA new entry
        if duplicate is None:
            self.distinct_items.append(new_item)
            return True

    """     ---------  Export functions ---------     """
    def export(self, _objects_matched, dest_path, export_file=""):

        reg_format_header = u"\ufeffWindows Registry Editor Version 5.00\r\n\r\n".encode("utf-16le")
        reg_files = []

        #items = _objects_matched.get_distinct_items()
        items = self.get_distinct_items(_objects_matched.get_items())

        for item in items:
            row = self._prepare_item(self.get_regedit_root_name(item["hive"].hive_type), item["key"], item["values"])

            # Export to single reg file
            if export_file:
                dest_filepath = export_file
            # Export to individual reg files
            else:
                dest_filepath = dest_path + '/' + item["hive"].file_name + '.reg'

            if row:
                if dest_filepath in reg_files:
                    with open(dest_filepath, mode="a+b") as file:
                        file.write(row)
                        file.close()
                else:
                    with open(dest_filepath, mode="a+b") as file:
                        file.write(reg_format_header)
                        file.write(row)
                        file.close()
                        reg_files.append(dest_filepath)
            else:
                pass  # Nothing to export

    def get_regedit_root_name(self, hive_type):
        # Hives are stored in HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\hivelist
        # Hive names explained in: https://msdn.microsoft.com/en-us/library/windows/desktop/ms724877(v=vs.85).aspx

        hives_mapping = {
            Registry.HiveType.SYSTEM: r"HKEY_LOCAL_MACHINE\SYSTEM",
            Registry.HiveType.SOFTWARE: r"HKEY_LOCAL_MACHINE\SOFTWARE",
            Registry.HiveType.DEFAULT: r"HKEY_USERS\.Default",
            Registry.HiveType.NTUSER: r"HKEY_CURRENT_USER",
            Registry.HiveType.SAM: r"HKEY_LOCAL_MACHINE\SAM",
            Registry.HiveType.SECURITY: r"HKEY_LOCAL_MACHINE\SECURITY",
            Registry.HiveType.USRCLASS: r"HKEY_CURRENT_USER\Software\Classes",
            Registry.HiveType.BCD: r"HKEY_LOCAL_MACHINE\BCD00000000"
        }

        if hive_type in hives_mapping:
            return hives_mapping[hive_type]
            parser.debug_print("ERROR: Unknown reg_root. Contact TheWit0k!")
        else:
            return "UNKNOWN"

    """     ---------  Format functions ---------     """
    def _reg_sz(self, value):
        return "\"{value}\"".format(value=value.value())

    def _reg_qword(self, value):

        s = ""
        try:
            for c in value.raw_data():
                s += ("%02x" % c) + ","
        except TypeError:
            return "ERROR_PARSER_REGISTRY_VALUE_TYPE_ERROR"

        s = "hex(b):" + s

        # Strips "," if it's last char
        if s[-1:] == ",":
            s = s[:-1]

        return s + "\r\n"

    def _reg_dword(self, value):
        """
        @rtype: str
        """
        return "dword:%08x" % (value.value())

    def _reg_bin(self, value):
        """
        The function exports the value to binary format supported by Windows Registry Editor Version 5.00

        - Example result (First line 79 chars, remaining lines <=78 chars):

        "test_bin"=hex:e7,e7,89,59,55,93,50,32,05,59,32,69,39,76,36,93,44,38,34,96,34,\  <- 79 chars
          96,36,93,96,39,63,93,46,4e,f8,f9,f4,09,6f,96,69,6d,9f,59,92,65,40,f9,fe,f5,\   <- 78 chars
          f0,dd,28,c2,4c,0a,c0,c2,06                                                     <- X remaining chars (<=78)
        """
        ret = []
        s = ""

        try:
            for c in value.value():
                s += ("%02x" % c) + ","
        except TypeError:
            return "ERROR_PARSER_REGISTRY_VALUE_TYPE_ERROR"

        # Strips "," if it's last char
        if s[-1:] == ",":
            s = s[:-1]

        if value.value_type() == Registry.RegBin:
            s = "hex:" + s
        else:
            s = "hex(%d):" % (value.value_type()) + s

        """ Prepare export data """
        name_len = len(value.name()) + 2 + 1 + 1  # name + 2 * '"' + 1 * '=' + 1 * '\'
        split_index = 80 - name_len
        while len(s) > 0:
            if len(s) > split_index:
                # split on a comma
                while s[split_index] != ",":
                    split_index -= 1
                ret.append(s[:split_index + 1] + "\\")
                s = "  " + s[split_index + 1:]
            else:
                ret.append(s)
                s = ""
            split_index = 78  # 80 - 2 * " " <- From 2nd line, the beginning of the line, starts from two empty spaces

        return "\r\n".join(ret)

    def _reg_msz(self, value):
        """
        REG_MULTI_SZ A sequence of null-terminated strings, terminated by an empty string (\0).
        - Virus\0Malware\0\0 -> 56,00,69,00,72,00,75,00,73,00,00,00,4d,00,61,00,6c,00,77,\
        00,61,00,72,00,65,00,00,00,00,00
        """
        s = ""
        ret = []

        try:
            for c in value.raw_data():
                s += ("%02x" % c) + ","
        except TypeError:
            return "ERROR_PARSER_REGISTRY_VALUE_TYPE_ERROR"

        # Strips "," if it's last char
        if s[-1:] == ",":
            s = s[:-1]

        s = "hex(%d):" % (value.value_type()) + s

        """ Prepare export data """
        name_len = len(value.name()) + 2 + 1 + 1  # name + 2 * '"' + 1 * '=' + 1 * '\'
        split_index = 80 - name_len
        while len(s) > 0:
            if len(s) > split_index:
                # split on a comma
                while s[split_index] != ",":
                    split_index -= 1
                ret.append(s[:split_index + 1] + "\\")
                s = "  " + s[split_index + 1:]
            else:
                ret.append(s)
                s = ""
            split_index = 78  # 80 - 2 * " " <- From 2nd line, the beginning of the line, starts from two empty spaces

        return "\r\n".join(ret)

    def reg_format_value(self, value):
        try:
            return {
                Registry.RegSZ: self._reg_sz,
                Registry.RegExpandSZ: self._reg_sz,
                Registry.RegBin: self._reg_bin,
                Registry.RegDWord: self._reg_dword,
                Registry.RegQWord: self._reg_qword,
                Registry.RegMultiSZ: self._reg_msz
            }[value.value_type()](value)
        except KeyError:
            print(f'ERROR - reg_format_value -> KeyError: {value}')

    def _prepare_item(self, prefix, key, values):
        """
        @rtype: byte string
        """
        ret = []
        path = key.path().partition("\\")[2]  # remove root key name ("$$$PROTO_HIV")
        ret.append(u"[{prefix}\{path}]".format(prefix=prefix, path=path))

        if not isinstance(values, list):
            values = [values]

        for value in values:
            if value:
                ret.append("\"{name}\"={value}".format(name=value.name(), value=self.reg_format_value(value)))

        ret.append("\r\n")
        return u"\r\n".join(ret).encode("utf-16le")
        # return u"\r\n".join(ret)


class _RegistryValue():
    obj = None
    name = ""
    name_unicode = ""
    type = None
    type_str = ""
    content = ""
    content_str = ""
    content_unicode = ""
    value_key_path = ""


    def __init__(self, RegistryValueObj, _obj_matched_item):

        if RegistryValueObj:

            self.obj = RegistryValueObj
            self.value_key_path = _obj_matched_item["key"].path()

            try:
                self.name = RegistryValueObj.name()
            except Exception as err:
                print(
                    f'ERROR: RegistryValue.__init__ -> {self.value_key_path}\\{self.name} [{self.type_str}]')
                self.name = "PARSER_VALUE_NAME_EXCEPTION"

            self.type = RegistryValueObj.value_type()
            self.type_str = RegistryValueObj.value_type_str()

            self.name_unicode = bytes(self.name, "utf-16le")

            try:
                self.content = RegistryValueObj.value()
            except Exception as err:
                print(
                    f'ERROR: RegistryValue.__init__ -> {self.value_key_path}\\{self.name} [{self.type_str}]')
                self.content = "PARSER_VALUE_VALUE_EXCEPTION"

            self.size = len(RegistryValueObj.raw_data())
            self.content_str = str(self.content)

            try:
                if self.type == Registry.RegBin:
                    self.content_unicode = self.content
                else:
                    self.content_unicode = RegistryValueObj.raw_data()
            except Exception as err:
                print(
                    f'ERROR: RegistryValue.__init__ -> {self.value_key_path}\\{self.name} [{self.type_str}]')
                self.content_unicode = "PARSER_VALUE_VALUE_UNICODE_EXCEPTION"

class _RegistryKey():

    path = ""
    path_unicode = ""
    timestamp = ""
    subkeys_count = 0
    values_count = 0

    def __init__(self, _obj_matched_item):
        RegistryKeyObj = _obj_matched_item["key"]

        if RegistryKeyObj:
            self.path = RegistryKeyObj.path()
            self.path_unicode = bytes(self.path, "utf-16le")
            self.timestamp = str(RegistryKeyObj.timestamp())
            self.values_count = len(RegistryKeyObj.values())
            self.subkeys_count = len(RegistryKeyObj.subkeys())
