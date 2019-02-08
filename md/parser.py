#import time
#import md.mem_profile as mem

import os
import re
import hashlib
import time
import csv
from dateutil import parser as date_parser # pip install python-dateutil
from Registry import Registry
from md.registry import registry, _RegistryKey, _RegistryValue
from md.decompressor import *
from md.baseline import *

"""
TO DO:
- Create a plugin: http://www.hexacorn.com/blog/2018/08/04/beyond-good-ol-run-key-part-83/
- Can we use it? https://github.com/msuhanov/yarp
- Adopt query_key_recursive / create new param
- Adopt query_value_wd to new style
- Add support to custom modules (Flagging suspcicious content of value name, or value contnet etc.) -> http://www.hexacorn.com/blog/2018/01/04/yet-another-way-to-hide-from-sysinternals-tools/ 
- Improve wildcard support in query_value_wd (Dynamic count of *)
- Improve error handling (settings.py etc.)
- Add multi threading support (Model: One thread per hive)
- Plugin to pull proxy settings: proxy 
- Plugin for decoding Tasks: tasks (Include COM object resolution: https://enigma0x3.net/2016/05/25/userland-persistence-with-scheduled-tasks-and-com-handler-hijacking/)
- Plugin for extensions hijacking: extensions -> (\Software\Classes\.extension -> shell\open\command registry key etc. )
- Plugin to find IP address history: network
- Plugin like: http://www.nirsoft.net/utils/encrypted_registry_view.html
- Plugin for COM objects? : https://gist.github.com/subTee/197a5ad2f49b4eed77aca0e637a1db9c, https://enigma0x3.net/2016/05/25/userland-persistence-with-scheduled-tasks-and-com-handler-hijacking/
- Plugin: Shellbags -> https://www.youtube.com/watch?v=YvVemshnpKQ
- @Witold: Check if user permissions can be queried  (Hidden keys by permission)…

"""
class parser(object):

    objects_matched = None

    format_fields = {
        "special": "",
        "key_timestamp": "",
        "key_subkeys": "",
        "key_values": "",
        "key_path": "",
        "key_path_unicode": "",
        "hive_type": "",
        "hive_path": "",
        "hive_name": "",
        "hive_root": "",
        "user_sid": "",
        "key_value": "",
        "value_type": "",
        "value_type_str": "",
        "value_name": "",
        "value_content": "",
        "value_content_hash": "",
        "value_size": "",
        "value_name_unicode": "",
        "value_content_unicode": "",
        "plugin": "",
        "plugin_name": "parser"
    }

    def __init__(self, args):
        try:
            if not self.check_args(args):
                self.initialized = False
            else:
                self.args = args
                self.debug_enabled = args.debug_enabled
                self.input_files = self._scan_input_path(args.input_folder)
                self.output_file = args.output_file
                self.search_criteria = _search_criteria(self.args)
                self.objects_matched = _objects_matched()
                self.registry = registry()
                self.output_format = args.output_format
                self.field_delimiter = args.field_delimiter
                self.loaded_plugins = []
                if args.sql_format:
                    self.db = db(self.output_file)
                    if self.db.connection:
                        self.db.create()
                self.initialized = True
        except Exception as error:
            print("ERROR: parser init(): Error Details:", error)
            self.initialized = False

    def execute(self):
        """ Execute -> Triggers the search or querying functions """

        """ Print debug data """
        # Get all hives for parsing
        self.debug_print(f'Loading hives from: {self.search_criteria.input_folder}')

        self.debug_print(f'Hives:')
        self.debug_print(self.input_files, "-")

        # Print what you will search for
        self.debug_print("\nParameters:")

        if self.search_criteria.export_folder != "":
            self.debug_print("- Export to: %s" % self.search_criteria.export_folder)

        self.debug_print("- Case sensitive: %s" % self.search_criteria.case_sensitive)
        self.debug_print("\nSearch entries:")

        for search_entries in (self.search_criteria.value_pattern, self.search_criteria.key_pattern,
                               self.search_criteria.data_pattern, self.search_criteria.timestamp_pattern):
            if search_entries:
                for entry in search_entries:
                    self.debug_print(
                        "- { %s  |   %s  |   %s }" % (entry.content_type, entry.content_format, entry.content))

        """ Execute accordingly """
        if self.args.query_value:  # QUERY VALUE
            for hive in self.input_files:
                #self.query_value(hive, self.search_criteria.query_value)
                self.query_value_wd(hive, self.search_criteria.query_value)

        if self.args.query_key:  # "QUERY KEY"
            for hive in self.input_files:
                self.query_key(hive, self.search_criteria.query_key)

        if self.search_criteria.query_subkeys:  # QUERY SUBKEYS
            for hive in self.input_files:
                self.query_root_subkeys(hive)

        search_param_list = (
        self.args.key_modified, self.args.key_string, self.args.key_regex, self.args.key_bin, self.args.value_string, self.args.value_regex,
        self.args.value_bin, self.args.data_string, self.args.data_regex, self.args.data_bin, self.args.data_size, self.args.key_modified_dt)

        _param = [param for param in search_param_list if param is not None]
        if _param:  # "SEARCH"
            for hive in self.input_files:
                self.search_registry(hive)

        """ Print the list of matched items """
        self.print_items()


        """ Export matched registry keys/values to .reg file, if export was enabled """
        # Export to single file, shall override the export to a folder
        if self.search_criteria.export_file:
            self.export_items()
        else:
            if self.search_criteria.export_folder:
                self.export_items()

    def check_args(self, args):
        """ Check arguments for their expected values """

        """ Check Output  """
        if args.sql_format:
            if not args.output_file:
                print(f"ERROR: SYNTAX ERROR -> -o <file-path> required when the output is set to SQLite3")
                return False

        """ Check output_format, so far only normalize it """
        if not isinstance(args.output_format, list):
            args.output_format = re.sub(r"[\s+]", "", args.output_format)  # remove whitespace

            if args.output_format_all:
                self.format_fields.pop("plugin")
                # self.output_format = ",".join(self.format_fields.keys())
                args.output_format = list(self.format_fields.keys())
            else:
                args.output_format = args.output_format.split(",")

        """ Check output file """
        fhandle = object
        try:
            if args.output_file:
                with open(args.output_file, 'w') as fhandle:
                    if not args.sql_format:
                        fhandle.write(args.field_delimiter.join(args.output_format) + '\n')
                    fhandle.close()
        except Exception as err:
            print(f"ERROR: {err}")
            exit(-1)

        """ If at least on binary argument specified, the mode is enforced to case-sensitive"""
        if [param for param in [args.key_bin, args.value_bin, args.data_bin] if param is not None]:
            if not args.case_sensitive:
                args.case_sensitive = True
                print(f"WARNING: Binary arguments (-kb, -vb, -db) do not support case insensitive mode. Enabling cases-sensitive mode...")

        """ Check Escaped UTF-8 syntax for binary search params"""
        for param in [args.key_bin, args.value_bin, args.data_bin]:
            if param:
                if not re.fullmatch(r'(?i)^(\\x([0-9][A-F]|[A-F][0-9]|[A-F]{2}|[0-9]{2}))+', param):
                    print(f"ERROR: SYNTAX ERROR -> Binary param: {param}")
                    return False

        """ Check data delimiter, which should be an ASCII string"""
        if args.field_delimiter != ",":
            try:
                args.field_delimiter.encode('ascii')
            except UnicodeEncodeError:
                print(
                    f"ERROR: ERROR_PARSER_ARGS_INCORRECT_DELIMITER_FORMAT -> The output delimiter must be ASCII string!")
                return False

        """ Check -td param format """
        pattern_list = _search_criteria.to_list(self, args.key_modified_dt)
        if pattern_list:
            _dt = _date_time()
            for pattern_str in pattern_list:
                if not _dt.check_param(pattern_str):
                    print(f"ERROR: Syntax error. Param: -td '{pattern_str}'")
                    exit(-1)
                else:
                    continue

        """ Check -dl param format """
        pattern_list = _search_criteria.to_list(self, args.data_size)
        if pattern_list:
            _dl = _data_size()
            for pattern_str in pattern_list:
                if not _dl.check_param(pattern_str):
                    print(f"ERROR: Syntax error. Param: -dl '{pattern_str}'")
                    exit(-1)
                else:
                    continue
        return True

    """     ---------  Export Functions  ---------     """
    def export_items(self):
        self.registry.export(self.objects_matched, self.search_criteria.export_folder, self.search_criteria.export_file)

    def _save_output(self, row, separator):
        try:
            # encoding="utf-16le"
            with open(self.output_file, encoding="utf8", mode="a", newline='') as file:
                #row_generator = (str(w) for w in row)

                csvwriter = csv.writer(file, delimiter=self.field_delimiter)
                csvwriter.writerow(row)
                #file.write(separator.join(row_generator) + "\n")
                file.close()

        except FileNotFoundError:
            print(f"ERROR: No such file or directory: {self.output_file}")
            return False
        except UnicodeEncodeError:
            print(f"ERROR: Unexpected UnicodeEncodeError - Please send the hive file to wit0k")
            return False

    """     ---------  Printing functions ---------     """
    def _print(self, row, separator):

        if self.output_file:
            self._save_output(row, separator)
        else:
            print(*row, sep=separator)

    def _get_item(self, item, name, attribute):
        _value = None
        try:
            _value = getattr(item[name], attribute)

            """ Case: Strip root key from key.path """
            if attribute == "path":
                if "\\" in _value:
                    _root,_,_path = _value.partition("\\")
                    _value = _path
        except Exception as err:
            _value = ""
        finally:
            return _value

    def _print_item(self, index, item, output_format=None, separator=","):

        """ Fill-in all item parts -> Remark: If you update it, update format_fields dict and baseline.create function """
        all_item_fields = {
            "special": "",
            "key_timestamp": self._get_item(item, "key", "timestamp") + " UTC",
            "key_subkeys": self._get_item(item, "key", "subkeys_count"),
            "key_values": self._get_item(item, "key", "values_count"),
            "key_path": self._get_item(item, "key", "path"),
            "key_path_unicode": self._get_item(item, "key", "path_unicode"),
            "hive_type": self._get_item(item, "hive", "hive_type"),
            "hive_path": self._get_item(item, "hive", "file_path"),
            "hive_name": self._get_item(item, "hive", "file_name"),
            "hive_root": self._get_item(item, "hive", "root"),
            "user_sid": self._get_item(item, "hive", "user_sid"),
            "key_value": self._get_item(item, "key", "path"),
            "value_type": "",
            "value_type_str": "",
            "value_name": "",
            "value_content": "",
            "value_content_hash": "",
            "value_size": "",
            "value_name_unicode": "",
            "value_content_unicode": "",
            "plugin": item["plugin"],
            "plugin_name": "parser"
        }

        row = []
        insert_query = ""
        _field_values = ()
        _item_fields = {}

        """ Prepare INSERT query """
        if self.search_criteria.sql_format:
            fields = ""
            for field in output_format:
                fields += f"{field}, "
            fields = f"({fields[:-2]}) "

            values = ""
            for _v in range(0, len(output_format)):
                values += f"?, "

            values = f"({values[:-2]})"
            insert_query = f"INSERT INTO entries{fields} VALUES{values}"

        """ Prepare the dictionary """
        if isinstance(item["values"], list):
            if item["values"]:
                for _value in item["values"]:
                    _item_fields = all_item_fields
                    _item_fields["value_type"] = _value.type
                    _item_fields["value_type_str"] = _value.type_str
                    _item_fields["value_name"] = _value.name
                    _item_fields["value_content"] = _value.content
                    _item_fields["value_size"] = str(_value.size)
                    _item_fields["value_name_unicode"] = _value.name_unicode
                    _item_fields["value_content_unicode"] = _value.content_unicode
                    _item_fields["key_value"] = _item_fields["key_value"] + '\\' + _value.name

                    if "value_content_hash" in output_format:
                        try:
                            if _value.type_str == "RegSZ":
                                _item_fields["value_content_hash"] = hashlib.md5(_value.content.encode()).hexdigest()
                            elif _value.type_str == "RegExpandSZ":
                                _item_fields["value_content_hash"] = hashlib.md5(_value.content.encode()).hexdigest()
                            elif _value.type_str in ("RegDWord", "RegQWord"):
                                _item_fields["value_content_hash"] = hashlib.md5(str(_value.content).encode()).hexdigest()
                            elif _value.type_str == "RegBin":
                                _item_fields["value_content_hash"] = hashlib.md5(_value.content).hexdigest()
                            elif _value.type_str == "RegMultiSZ":
                                _item_fields["value_content_hash"] = hashlib.md5(_value.obj.raw_data()).hexdigest()
                            elif _value.type_str == "RegNone":
                                _item_fields["value_content_hash"] = "RegNone"
                            else:
                                _item_fields["value_content_hash"] = f"{_value.type_str} - Hashing not supported yet"
                        except TypeError as err:
                            _item_fields["value_content_hash"] = f"{_value.type_str} - Hashing Error: {err}"


                    """ Apply plugin specific modifications """
                    _plugin_obj = _item_fields["plugin"]

                    if _plugin_obj:
                        try:
                            _item_fields = _plugin_obj.format_data(_item_fields)
                            _item_fields["plugin_name"] = _item_fields["plugin"].name

                            if item['special']:
                                if _item_fields["special"] != item['special']:
                                    _item_fields["special"] = _item_fields["special"] + item['special']

                        except Exception:
                            self.debug_print("ERROR: _print_item() ->  format_data() failed")

                    """ Sets requested order of printed fields """
                    for _format_field in output_format:
                        try:
                            if self.search_criteria.sql_format:
                                _field_values += (str(_item_fields[_format_field]), )
                                row.append(_item_fields[_format_field])
                            else:
                                row.append(_item_fields[_format_field])
                        except KeyError:
                            self.debug_print(f"ERROR: _print_item() -> Unexpected key name: '{_format_field}'")

                    if self.search_criteria.sql_format:
                        self.db.query(insert_query, _field_values)
                        self._print(row, separator)
                    else:
                        self._print(row, separator)

                    _field_values = ()
                    row.clear()
            else:

                """ Apply plugin specific modifications """
                _plugin_obj = all_item_fields["plugin"]

                if _plugin_obj:
                    try:
                        all_item_fields = _plugin_obj.format_data(all_item_fields)
                        all_item_fields["plugin_name"] = all_item_fields["plugin"].name

                        if item['special']:
                            if all_item_fields["special"] != item['special']:
                                all_item_fields["special"] = all_item_fields["special"] + item['special']

                    except Exception:
                        self.debug_print("ERROR: _print_item() ->  format_data() failed")

                """ Sets requested order of printed fields """
                for _format_field in output_format:
                    try:
                        if self.search_criteria.sql_format:
                            _field_values += (str(all_item_fields[_format_field]),)
                            row.append(all_item_fields[_format_field])
                        else:
                            row.append(all_item_fields[_format_field])
                    except KeyError:
                        self.debug_print(f"ERROR: _print_item() -> Unexpected key name: '{_format_field}'")

                if self.search_criteria.sql_format:
                    self.db.query(insert_query, _field_values)
                    self._print(row, separator)
                else:
                    self._print(row, separator)

                _field_values = ()
                row.clear()

    def _parse_items(self, items):

        index = 0

        for item in items:
            index += 1
            values = []
            key = _RegistryKey(item)
            """ Case key has values """
            if item["key"].values():
                if isinstance(item["values"], list):
                    for _value in item["values"]:
                        value = _RegistryValue(_value, item)
                        values.append(value)
                else:
                    value = _RegistryValue(item["values"], item)
                    values.append(value)

            try:
                self._print_item(index, {"hive": item["hive"], "key": key, "values": values, "plugin": item["plugin"], 'special': item.get('special', None)},
                                 self.output_format, self.field_delimiter)
            except AttributeError:
                self.debug_print(f"ERROR: _parse_items() -> Possibly plugin related error")
            except KeyError:
                self._print_item(index, {"hive": item["hive"], "key": key, "values": values, "plugin": None, 'special': item.get('special', None)},
                                 self.output_format, self.field_delimiter)
            except Exception as e:
                self.debug_print(f"ERROR: _parse_items() -> Unexpected exception: {str(e)}")

    def print_items(self):
        items = self.objects_matched.get_items()
        if items:
            self._parse_items(items)

    def debug_print(self, message, prefix=""):

        _time = time.strftime("%Y-%m-%d %H:%M:%S")

        if self.debug_enabled:
            if isinstance(message, list):
                for element in message:
                    if prefix is not "":
                        print(_time, prefix, element)
                    else:
                        print(_time, element)
            else:
                if prefix is not "":
                    print(_time, prefix, message)
                else:
                    print(_time, message)

    """     ---------  Hive Management  ---------     """
    def _scan_input_path(self, input_path, filter_path="", disable_recursive=False):
        """
            - Accepts file (hive, compressed hive) or a folder containing a mix of hive(s) and compressed hive(s).
            - The input folder can be scanned recursively
            - Recursive mode is overridden (by default) when a single compressed file is specified as input_path
        """

        if os.path.isfile(input_path):
            """ Decompress supported archives """
            file_extension = os.path.splitext(input_path)[1].upper()
            file_parent_folder = os.path.dirname(input_path)
            if file_extension in supported_archive_extensions():
                decompress(input_path)
                return self._scan_input_path(file_parent_folder, input_path, True)
            else:
                return [input_path]

        if not os.path.isdir(input_path):
            print(f'ERROR_PARSER_INPUT_FOLDER_NOT_FOUND: {ERROR_PARSER_INPUT_FOLDER_NOT_FOUND} -> {input_path}')
            exit(ERROR_PARSER_INPUT_FOLDER_NOT_FOUND)

        hives_folders = []
        hives = []

        """ Special case: Override args setting (archive specified in input_path """
        if disable_recursive:
            self.args.recursive = False

        """ Enumerate al subfolders (if recursive enabled) """
        if self.args.recursive:
            for root, subdirs, files in os.walk(input_path):
                hives_folders.append(root)
        else:
            hives_folders.append(input_path)


        """ Decompress supported archives """
        for folder in hives_folders:
            # Prepare a list of filepaths to registry hives
            for file in os.listdir(folder):
                file_path = folder + r"/" + file
                if os.path.isfile(file_path) and filter_path in file_path:
                    file_extension = os.path.splitext(file_path)[1].upper()
                    file_parent_folder = os.path.join(file_path, os.pardir)

                    if file_extension in supported_archive_extensions():
                        decompress(file_path)

        EXCLUDED_EXTENSIONS = (
            ".ZIP",
            ".7Z",
            ".DS_STORE",
            ".REG"
        )

        """ Enumerate all files (including decompressed files"""
        for folder in hives_folders:
            for file in os.listdir(folder):
                file_path = folder + r"/" + file
                if os.path.isfile(file_path) and filter_path in file_path:

                    if not file_path.upper().endswith(EXCLUDED_EXTENSIONS):
                        hives.append(file_path)
                    else:
                        self.debug_print(f'INFO: Excluding: {file_path} from enumeration')


        if hives:
            return hives
        else:
            self.debug_print(f'ERROR_PARSER_INPUT_FOLDER_EMPTY: {ERROR_PARSER_INPUT_FOLDER_EMPTY}')
            exit(ERROR_PARSER_INPUT_FOLDER_EMPTY)

    def _load_hive(self, hive_file):
        try:
            self.debug_print(f"INFO: Loading hive: {hive_file}")
            reg_obj = Registry.Registry(hive_file)
            registry_hive = _registry_hive(os.path.basename(hive_file), hive_file, reg_obj)
            registry_hive.hive_type = registry_hive.reg.hive_type()
            _root = registry_hive.reg.root().path()
            registry_hive.root = _root

            """ Get user SID for NTUSER hives"""
            if registry_hive.hive_type == Registry.HiveType.NTUSER:
                try:
                    registry_hive.user_sid = reg_obj.open("Software\Microsoft\Protected Storage System Provider").subkeys()[0].path()
                except Registry.RegistryKeyNotFoundException:
                    registry_hive.user_sid = ""
                finally:
                    _key_path, _, _value_name = registry_hive.user_sid.rpartition("\\")

                    if _value_name:
                        registry_hive.user_sid = _value_name

            return registry_hive
        except Exception as error:

            with open(hive_file, 'r', encoding='utf-8', errors='ignore') as f:
                header = f.read(8)

            self.debug_print(f'ERROR: _load_hive({hive_file}) -> {error} -> Header:  {header.encode("utf-8")} [{header}]')
            return None

    """     ---------  Registry Querying  ---------     """
    # (self, hive_file, key_value_strings, registry_hive = None, return_result = False)
    def query_value_wd(self, hive_file, key_value_strings, registry_hive = None, return_result = False):
    # def query_value_wd(self, hive_file, key_value_strings):
        """ The function would query the key for given values, if successful, it updates objects_matched list """

        if key_value_strings:
            values = []
            if not registry_hive:
                registry_hive = self._load_hive(hive_file)

            if not registry_hive:
                return ERROR_PARSER_REG_HIVE_NOT_SUPPORTED

            """ Loop trough all value names given in the command line """
            for _key_value in key_value_strings:

                try:
                    """ Check _key_value syntax """
                    if _key_value.startswith("\\"):
                        self.debug_print(f"WARNING: Registry Key\Value: {_key_value} -> Syntax Error")
                        continue

                    """ Check if wildcard was used """
                    if '\\*\\' in _key_value: # Check for the input shall be better in the next version
                        _key_path, _, _value_name = _key_value.rpartition("*")
                        _value_name = _value_name[1:]
                        _key_path = _key_path[:-1]
                        _root_key = _key_path

                        """ Load the root key """
                        self.debug_print(f"Opening root: {_root_key}")
                        try:
                            key = registry_hive.reg.open(_root_key)
                        except Registry.RegistryKeyNotFoundException:
                            self.debug_print(
                                f'{registry_hive.file_path} -> {_root_key}: "ERROR_PARSER_KEY_NOT_FOUND')
                            continue
                        except Exception as msg:
                            self.debug_print(
                                '{registry_hive.file_path} -> %s: "Python registry internal error: %s' % (
                                registry_hive.file_path, str(msg)))
                            continue

                        """ Check if key has any subkeys """
                        if key.subkeys():

                            """ Resolve Subkey names """
                            _sub_keys = key.subkeys()

                            for _sub_key in _sub_keys:
                                try:
                                    self.debug_print(f'- QUERY VALUE -> %s\%s' % (_sub_key.path(), _value_name))
                                    _value = _sub_key.value(_value_name)

                                    if _value:
                                        if return_result:
                                            values.append({"hive": registry_hive, "key": _sub_key, "values": [_value]})
                                        else:
                                            self.objects_matched.append(
                                                {"hive": registry_hive, "key": _sub_key, "values": [_value]})
                                    else:
                                        if return_result:
                                            values.append({"hive": registry_hive, "key": _sub_key, "values": []})
                                        else:
                                            self.objects_matched.append(
                                                {"hive": registry_hive, "key": _sub_key, "values": []})

                                    # self.objects_matched.append({"hive": registry_hive, "key": _sub_key, "values": [_value]})

                                except Registry.RegistryValueNotFoundException:
                                    self.debug_print(
                                        f'- QUERY VALUE -> {_sub_key.path()}\\{_value_name}' + ' [ERROR_PARSER_VALUE_NOT_FOUND]')
                                    continue
                        else:
                            self.debug_print(
                                f'{registry_hive.file_path} -> {_key_path}: "No subkeys found!')

                    else:
                        result = self.query_value(hive_file, [_key_value], registry_hive, return_result)
                        values.append(result)


                except Registry.RegistryKeyNotFoundException:
                    self.debug_print(
                        f'{registry_hive.file_path} -> {_key_path}: "ERROR_PARSER_KEY_NOT_FOUND')
                    continue

            return values
        else:
            self.debug_print("ERROR: QUERY VALUE -> Nothing to query...")
            return None

    def query_value(self, hive_file, key_value_strings, registry_hive=None, return_result=False):
        """ The function would query the key for given values, if successful, it updates objects_matched list """
        if key_value_strings:
            values = []
            """ Load hive - would return the object of type: _registry_hive() """
            if not registry_hive:
                registry_hive = self._load_hive(hive_file)

            if not registry_hive:
                return ERROR_PARSER_REG_HIVE_NOT_SUPPORTED

            """ Loop trough all value names given in the command line """
            for _key_value in key_value_strings:

                _key_path, _, _value_name = _key_value.rpartition("\\")

                self.debug_print(f"- QUERY VALUE: %s\%s" % (registry_hive.file_name, _key_value))
                try:
                    key = registry_hive.reg.open(_key_path)
                except Registry.RegistryKeyNotFoundException:
                    self.debug_print(
                        '{registry_hive.file_path} -> %s: "ERROR_PARSER_KEY_NOT_FOUND' % registry_hive.file_path)
                    continue
                except Exception as msg:
                    self.debug_print(
                        '{registry_hive.file_path} -> %s: "Python registry internal error: %s' % (registry_hive.file_path, str(msg)))
                    continue

                try:
                    value = key.value(_value_name)
                    if value:
                        if return_result:
                            values.append({"hive": registry_hive, "key": key, "values": [value]})
                        else:
                            self.objects_matched.append({"hive": registry_hive, "key": key, "values": [value]})
                    else:
                        if return_result:
                            values.append({"hive": registry_hive, "key": key, "values": []})
                        else:
                            self.objects_matched.append({"hive": registry_hive, "key": key, "values": []}) # it's a fix to the framework error: RegistryStructureDoesNotExist
                except Registry.RegistryValueNotFoundException:
                    self.debug_print(
                        f'{registry_hive.file_path} -> {_key_path}\{_value_name}: "ERROR_PARSER_VALUE_NOT_FOUND"')

            return values
        else:
            self.debug_print("ERROR: QUERY VALUE -> Nothing to query...")
            return []

    def query_key_recursive(self, registry_hive, key, objects_matched=[], depth=0):

        if depth == 0:
            if not registry_hive:
                print(f"ERROR: query_key_recursive() -> registry_hive not initialized")
                exit(-1)
            objects_matched.append({"hive": registry_hive, "key": key, "values": key.values()})

        for subkey in key.subkeys():
            objects_matched.append({"hive": registry_hive, "key": subkey, "values": subkey.values()})

            self.query_key_recursive(registry_hive, subkey, objects_matched, depth + 1)

    def query_key(self, hive_file, keys, registry_hive=None, return_result=False):
        """ Load hive - would return the object of type: _registry_hive() """
        if keys:
            _keys = []
            """ Load hive - would return the object of type: _registry_hive() """
            if not registry_hive:
                registry_hive = self._load_hive(hive_file)

            if not registry_hive:
                # ERROR_PARSER_REG_HIVE_NOT_SUPPORTED
                return _keys

            for _key in keys:
                """ Wildcard check - Case: Recursive query """
                recursive = False
                if r'\*' in _key:
                    _key, _, junk = _key.rpartition("*")
                    _key = _key[:-1]
                    self.debug_print(f"- QUERY KEY (Recursive): %s\%s" % (registry_hive.file_name, _key))
                    recursive = True
                else:
                    self.debug_print(f"- QUERY KEY: %s\%s" % (registry_hive.file_name, _key))

                try:
                    key = registry_hive.reg.open(_key)
                except Registry.RegistryKeyNotFoundException:
                    self.debug_print(f'{registry_hive.file_path} -> {_key}: "ERROR_PARSER_KEY_NOT_FOUND"')
                    continue
                except Exception as msg:
                    self.debug_print(
                        '{registry_hive.file_path} -> %s: "Python registry internal error: %s' % (
                            registry_hive.file_path, str(msg)))
                    continue

                if recursive:
                    self.query_key_recursive(registry_hive, key, _keys)
                    if not return_result:
                        self.objects_matched.extend(_keys)
                    continue

                values = []
                if key.values():
                    for value in key.values():
                        values.append(value)

                if return_result:
                    _keys.append({"hive": registry_hive, "key": key, "values": values})
                else:
                    self.objects_matched.append({"hive": registry_hive, "key": key, "values": values})

            return _keys

        else:
            self.debug_print("ERROR: QUERY KEY -> Nothing to query...")
            return []

    def query_root_subkeys(self, hive_file):
        """ Load hive - would return the object of type: _registry_hive() """
        registry_hive = self._load_hive(hive_file)

        if not registry_hive:
            return ERROR_PARSER_REG_HIVE_NOT_SUPPORTED

        values = []
        self.debug_print("- QUERY SUBKEYS -> %s" % registry_hive.file_path)
        key = registry_hive.reg.root()

        if key.subkeys():
            for _key in key.subkeys():
                _root_key, _, _key_ = _key.path().partition("\\")
                print(f"{registry_hive.file_path}{self.field_delimiter}{_key_}")

    """     ---------  Registry Searching  ---------     """
    def _evaluate_search_criteria_case_i(self, registry_hive, Key):

        values_matched = []
        key_path = Key.path().upper()

        """  ------------------    KEY CRITERIA   ------------------  """
        if self.search_criteria.key_pattern:
            for search_entry in self.search_criteria.key_pattern:
                if search_entry.content_format == "STRING":
                    if search_entry.content in key_path:
                        self.objects_matched.append({"hive": registry_hive, "key": Key, "values": Key.values()})
                        return
                    continue

                if search_entry.content_format == "REGEX":
                    if search_entry.content.search(key_path):
                        self.objects_matched.append({"hive": registry_hive, "key": Key, "values": Key.values()})
                        return

                if search_entry.content_format == "BIN":
                    if search_entry.content in bytes(key_path, "utf-16le"):
                        self.objects_matched.append({"hive": registry_hive, "key": Key, "values": Key.values()})
                        return
                    continue

        """  ------------------    TIMESTAMP CRITERIA   ------------------  """
        if self.search_criteria.timestamp_pattern:
            for search_entry in self.search_criteria.timestamp_pattern:

                if search_entry.content_format == "REGEX":
                    if search_entry.content.search(str(Key.timestamp())):
                        self.objects_matched.append({"hive": registry_hive, "key": Key, "values": Key.values()})
                        return
                    continue

                if search_entry.content_format == "TIMESTAMP":
                    if search_entry.content.match(Key.timestamp()):
                        self.objects_matched.append({"hive": registry_hive, "key": Key, "values": Key.values()})
                        return

        """  ------------------    VALUE CRITERIA   ------------------  """
        if self.search_criteria.value_pattern:
            for search_entry in self.search_criteria.value_pattern:
                for _value in Key.values():
                    if search_entry.content_format == "STRING":
                        if search_entry.content in _value.name().upper():
                            values_matched.append(_value)
                            #print(bytes(_value.name(), "utf-8").hex())
                        continue

                    if search_entry.content_format == "REGEX":
                        if search_entry.content.search(_value.name()) is not None:
                            values_matched.append(_value)
                        continue

                    if search_entry.content_format == "BIN":
                        if search_entry.content in bytes(_value.name(), "utf-16le"):
                            values_matched.append(_value)

        """  ------------------    DATA CRITERIA   ------------------  """
        if self.search_criteria.data_pattern:
            for _value in Key.values():
                for search_entry in self.search_criteria.data_pattern:
                    if search_entry.content_format == "STRING":
                        if search_entry.content in str(_value.value()).upper():
                            values_matched.append(_value)
                        continue

                    if search_entry.content_format == "REGEX":
                        if search_entry.content.search(str(_value.value())) is not None:
                            values_matched.append(_value)
                        continue

                    if search_entry.content_format == "BIN":
                        try:
                            if not (_value.raw_data()).find(search_entry.content) == -1:
                                values_matched.append(_value)
                                continue
                        except TypeError:
                            if not (_value.raw_data().encode()).find(search_entry.content) == -1:
                                values_matched.append(_value)
                                continue
                        continue

                    if search_entry.content_format == "SIZE":
                        bytes_len = len(_value.raw_data())

                        if search_entry.content.match(bytes_len):
                            values_matched.append(_value)

        # Make sure to expose only these values/data that have matched the search criteria
        if values_matched:
            self.objects_matched.append({"hive": registry_hive, "key": Key, "values": values_matched})

    def _evaluate_search_criteria(self, registry_hive, Key):

        values_matched = []
        key_path = Key.path()

        """  ------------------    KEY CRITERIA   ------------------  """
        if self.search_criteria.key_pattern:
            for search_entry in self.search_criteria.key_pattern:
                if search_entry.content_format == "STRING":
                    if search_entry.content in key_path:
                        self.objects_matched.append({"hive": registry_hive, "key": Key, "values": Key.values()})
                        return

                if search_entry.content_format == "REGEX":
                    if search_entry.content.search(key_path):
                        self.objects_matched.append({"hive": registry_hive, "key": Key, "values": Key.values()})
                        return

                if search_entry.content_format == "BIN":
                    if search_entry.content in bytes(key_path, "utf-16le"):
                        self.objects_matched.append({"hive": registry_hive, "key": Key, "values": Key.values()})
                        return

        """  ------------------    TIMESTAMP CRITERIA   ------------------  """
        if self.search_criteria.timestamp_pattern:
            for search_entry in self.search_criteria.timestamp_pattern:

                if search_entry.content_format == "REGEX":
                    if search_entry.content.search(str(Key.timestamp())):
                        self.objects_matched.append({"hive": registry_hive, "key": Key, "values": Key.values()})
                        return

                if search_entry.content_format == "TIMESTAMP":
                    if search_entry.content.match(Key.timestamp()):
                        self.objects_matched.append({"hive": registry_hive, "key": Key, "values": Key.values()})
                        return

        """  ------------------    VALUE CRITERIA   ------------------  """
        if self.search_criteria.value_pattern:
            for search_entry in self.search_criteria.value_pattern:
                for _value in Key.values():
                    if search_entry.content_format == "STRING":
                        if search_entry.content in _value.name():
                            values_matched.append(_value)
                            continue
                    if search_entry.content_format == "REGEX":
                        if search_entry.content.search(_value.name()) is not None:
                            values_matched.append(_value)
                            continue
                    if search_entry.content_format == "BIN":
                        if search_entry.content in bytes(_value.name(), "utf-16le"):
                            values_matched.append(_value)
                            continue

        """  ------------------    DATA CRITERIA   ------------------  """
        if self.search_criteria.data_pattern:
            for _value in Key.values():

                for search_entry in self.search_criteria.data_pattern:
                    if search_entry.content_format == "STRING":
                        if search_entry.content in str(_value.value()):
                            values_matched.append(_value)
                            continue
                    if search_entry.content_format == "REGEX":
                        if search_entry.content.search(str(_value.value())) is not None:
                            values_matched.append(_value)
                            continue

                    if search_entry.content_format == "BIN":
                        try:
                            if not (_value.raw_data()).find(search_entry.content) == -1:
                                values_matched.append(_value)
                                continue
                        except TypeError:
                            if not (_value.raw_data().encode()).find(search_entry.content) == -1:
                                values_matched.append(_value)
                                continue

                    if search_entry.content_format == "SIZE":
                        bytes_len = len(_value.raw_data())

                        if search_entry.content.match(bytes_len):
                            values_matched.append(_value)
                            continue

        # Make sure to expose only these values/data that have matched the search criteria
        if values_matched:
            self.objects_matched.append({"hive": registry_hive, "key": Key, "values": values_matched})

    def _search_registry_ci(self, registry_hive, key, depth=0):
        # Search whole registry
        if depth == 0:
            try:
                self._evaluate_search_criteria_case_i(registry_hive, key)
            except Exception as ex:
                print(f"Exception: Key {key.path()} -> Error: {ex}")

        for subkey in key.subkeys():
            try:
                self._evaluate_search_criteria_case_i(registry_hive, subkey)
            except Exception as ex:
                print(f"Exception: Key {key.path()} -> Error: {ex}")
            self._search_registry_ci(registry_hive, subkey, depth + 1)

    def _search_registry_cs(self, registry_hive, key, depth=0):
        # Search whole registry
        if depth == 0:
            try:
                self._evaluate_search_criteria(registry_hive, key)
            except Exception as ex:
                print(f"Exception: Key {key.path()} -> Error: {ex}")

        for subkey in key.subkeys():
            try:
                self._evaluate_search_criteria(registry_hive, subkey)
            except Exception as ex:
                print(f"Exception: Key {key.path()} -> Error: {ex}")
            self._search_registry_cs(registry_hive, subkey, depth + 1)

    def search_registry(self, hive_file, depth=0):
        """ Load hive - would return the object of type: _registry_hive() """
        registry_hive = self._load_hive(hive_file)

        #print('Memory (Before): {}Mb'.format(mem.memory_usage_psutil()))
        #t1 = time.clock()

        if not registry_hive:
            return ERROR_PARSER_REG_HIVE_NOT_SUPPORTED

        if self.search_criteria.case_sensitive:
            self._search_registry_cs(registry_hive, registry_hive.reg.root())
        else:
            self._search_registry_ci(registry_hive, registry_hive.reg.root())

        #t2 = time.clock()
        #print('Memory (After): {}Mb'.format(mem.memory_usage_psutil()))
        #print('Took {} Seconds'.format(t2 - t1))


class _objects_matched(parser):

    items = []
    #distinct_items = []

    def __init__(self):
        pass

    def append(self, new_item):
        self.items.append(new_item)

    def get_items(self):
        return self.items

    def extend(self, new_items):
        self.items.extend(new_items)

    def clear(self):
        self.items.clear()

class _search_entry():
    content = None
    content_type = None  # KEY or VALUE
    content_format = None  # String or Regex or Binary

    def __init__(self, content, content_type, content_format):
        self.content = content
        self.content_type = content_type
        self.content_format = content_format

class _search_criteria():

    value_pattern = []
    key_pattern = []
    data_pattern = []
    timestamp_pattern = []

    input_folder = None
    recursive = None
    case_sensitive = None
    regex_flags = None
    unicode_enabled = None
    export_folder = None
    export_file = None
    initialized = None

    key_modified = []
    key_modified_dt = []
    key_string = []
    key_regex = []
    key_bin = []
    value_string = []
    value_regex = []
    value_bin = []
    data_string = []
    data_regex = []
    data_bin = []

    query_key = []
    query_value = []
    query_subkeys = None

    plugins_to_execute = []

    def to_list(self, param, separator=","):
        param_list = []
        if param:
            if isinstance(param, bytes):
                return [param]
            if isinstance(param, _data_size):
                return [param]
            if separator in param:
                for p in param.split(","):
                    param_list.append(p.strip())
            else:
                return [param]
        return param_list

    def to_entries(self, param_list, content_type, content_format):
        """
            - content_type -> KEY | VALUE | DATA | TIMESTAMP
            - content_format -> STRING | REGEX | BIN | SIZE | TIMESTAMP
        """
        entries = []
        if param_list:

            for param in param_list:
                if content_format == "STRING":
                    if not self.case_sensitive:
                        param = param.upper()

                    entries.append(_search_entry(param, content_type, content_format))

                if content_format == "REGEX":
                    regex_object = re.compile(param, flags=self.regex_flags)
                    entries.append(_search_entry(regex_object, content_type, content_format))

                if content_format == "BIN":

                    entries.append(_search_entry(unicode_string, content_type, content_format))

                if content_format == "SIZE":  # Applicable for value content size only
                    _data_size_obj = _data_size(param)
                    entries.append(_search_entry(_data_size_obj, content_type, content_format))

                if content_format == "TIMESTAMP":  # Applicable for value content size only
                    try:
                        # param = datetime.datetime.strptime(param, "%d-%m-%Y %H:%M:%S")
                        _date_time_obj = _date_time(param)
                        entries.append(_search_entry(_date_time_obj, content_type, content_format))
                    except Exception as err:
                        print(f"ERROR: to_entries(), content_format: TIMESTAMP, param:'{param}' ->  {err}")

        if "KEY" in content_type:
            self.key_pattern.extend(entries)
        if "VALUE" in content_type:
            self.value_pattern.extend(entries)
        if "DATA" in content_type:
            self.data_pattern.extend(entries)
        if "TIMESTAMP" in content_type:
            self.timestamp_pattern.extend(entries)

    def __init__(self, args):

        self.input_folder = args.input_folder

        if args.export_file:
            self.export_file = args.export_file

        if args.export_folder:
            if os.path.isdir(args.export_folder):
                self.export_folder = args.export_folder
            else:
                print("ERROR: Export folder not found!")
                exit(-1)

        self.recursive = args.recursive
        self.case_sensitive = args.case_sensitive

        if not self.case_sensitive:
            self.regex_flags = re.IGNORECASE
            parser.case_sensitive = False
        else:
            self.regex_flags = 0
            parser.case_sensitive = True

        #self.hash_content = args.hash_content
        self.sql_format = args.sql_format

        ''' -----------------------------  KEY  ------------------------------------'''
        self.key_modified = self.to_list(args.key_modified)
        if self.key_modified:
            self.to_entries(self.key_modified, "TIMESTAMP", "REGEX")

        self.key_modified_dt = self.to_list(args.key_modified_dt)
        if self.key_modified_dt:
            self.to_entries(self.key_modified_dt, "TIMESTAMP", "TIMESTAMP")


        self.key_string = self.to_list(args.key_string)
        if self.key_string:
            self.to_entries(self.key_string, "KEY", "STRING")

        self.key_regex = self.to_list(args.key_regex)
        if self.key_regex:
            self.to_entries(self.key_regex, "KEY", "REGEX")

        #utf16le_key_bin = bytes(args.key_bin, "utf-8").decode('unicode-escape').encode("utf-16le")
        self.key_bin = self.to_list(args.key_bin)
        if self.key_bin:
            parser.unicode_search_enabled = True
            self.to_entries(self.key_bin, "KEY", "BIN")

        ''' -----------------------------  VALUE  ------------------------------------'''
        self.value_string = self.to_list(args.value_string)
        if self.value_string:
            self.to_entries(self.value_string, "VALUE", "STRING")

        self.value_regex = self.to_list(args.value_regex)
        if self.value_regex:
            self.to_entries(self.value_regex, "VALUE", "REGEX")

        self.value_bin = self.to_list(args.value_bin)
        if self.value_bin:
            parser.unicode_search_enabled = True
            self.to_entries(self.value_bin, "VALUE", "BIN")

        ''' -----------------------------  DATA  ------------------------------------'''
        self.data_string = self.to_list(args.data_string)
        if self.data_string:
            self.to_entries(self.data_string, "DATA", "STRING")

        self.data_regex = self.to_list(args.data_regex)
        if self.data_regex:
            self.to_entries(self.data_regex, "DATA", "REGEX")

        self.data_bin = self.to_list(args.data_bin)
        if self.data_bin:
            parser.unicode_search_enabled = True
            self.to_entries(self.data_bin, "DATA", "BIN")

        if args.data_size:
            #_data_size.check_data_size_format(self, args, True)
            #self.data_size = self.to_list(args.data_size)  # The list is created in check_args
            self.data_size = self.to_list(args.data_size)
            self.to_entries(self.data_size, "DATA", "SIZE")

        ''' -----------------------------  QUERY KEY or VALUE  ------------------------------------'''
        self.query_key = self.to_list(args.query_key)
        self.query_value = self.to_list(args.query_value)
        self.query_subkeys = args.query_subkeys

        if args.plugins_to_execute:
            self.plugins_to_execute = self.to_list(args.plugins_to_execute)

        self.initialized = True

class _registry_hive():

    def __init__(self, file_name, hive_file, regobj=None, hive_type=None, user_sid="", root=""):
        self.file_name = file_name
        self.file_path = hive_file
        self.reg = regobj
        self.hive_type = hive_type
        self.user_sid = user_sid
        self.root = root

class _date_time():

    patterns = {
        "range_pattern": r'(^\d{4}[\/-]\d{2}[\/-]\d{2}.*)(..{1})(\d{4}[\/-]\d{2}[\/-]\d{2}.*)',
        "inequality_pattern_b": r'(^[>]{1})(\d{4}[\/-]\d{2}[\/-]\d{2}.*)',
        "inequality_pattern_s": r'(^[<]{1})(\d{4}[\/-]\d{2}[\/-]\d{2}.*)',
        "equality_patern": r'(^[=]{1})(\d{4}[\/-]\d{2}[\/-]\d{2}.*)'  # Pattern is good, but match does not work well, better to use -tm for it anyway.
    }

    def __init__(self, param_str=None):

        self.start_date = None
        self.end_date = None
        self.operator = None
        self.initialized = None

        if param_str:
            if self.import_param(param_str):
                self.initialized = True

    def check_param(self, param_str):
        """ Return True if param_str match a pattern """
        param_groups = None
        """ Initial param cosmetic adjustment  """
        param_str = param_str.strip()

        """ Cherck the param syntax """
        for key, pattern in self.patterns.items():
            param_groups = re.fullmatch(pattern, param_str)
            if param_groups:
                return True
        return False

    def match(self, key_timestamp):

        if self.initialized:
            if self.operator == "..":
                if key_timestamp >= self.start_date and key_timestamp <= self.end_date:
                    return True

            if self.operator == ">":
                if key_timestamp > self.start_date:
                    return True

            if self.operator == "<":
                if key_timestamp < self.start_date:
                    return True

            if self.operator == "=":
                if key_timestamp == self.start_date:
                    return True
            
        return False

    def import_param(self, param_str):
        """ Return True if import is successful  """
        param_groups = None
        """ Initial param cosmetic adjustment  """
        # re.sub(r"\s+", "", param, flags=re.UNICODE)  #  Removes all white spaces
        param_str = param_str.strip()

        """ Cherck the param syntax """
        for key, pattern in self.patterns.items():
            param_groups = re.findall(pattern, param_str)
            if param_groups:
                # Range
                if len(param_groups[0]) == 3:
                    self.start_date = date_parser.parse(param_groups[0][0])
                    self.operator = param_groups[0][1]
                    self.end_date = date_parser.parse(param_groups[0][2])
                else:
                    # Other equality, inequality
                    self.operator = param_groups[0][0]
                    self.start_date = date_parser.parse(param_groups[0][1])

                return True

        return False

class _data_size():
    patterns = {
        "range_pattern": r'(^\d+)(..{1})(\d+)',
        "inequality_pattern_b": r'(^[>]{1})(\d+)',
        "inequality_pattern_s": r'(^[<]{1})(\d+)',
        "equality_patern": r'(^[=]{1})(\d+)'
    }

    def __init__(self, param_str=None):

        self.first_number = None
        self.second_number = None
        self.operator = None
        self.initialized = None

        if param_str:
            if self.import_param(param_str):
                self.initialized = True

    def check_param(self, param_str):
        """ Return True if param_str match a pattern """
        param_groups = None
        """ Initial param cosmetic adjustment  """
        param_str = param_str.strip()

        """ Cherck the param syntax """
        for key, pattern in self.patterns.items():
            param_groups = re.fullmatch(pattern, param_str)
            if param_groups:
                return True
        return False

    def match(self, data_size):

        if self.initialized:
            if self.operator == "..":
                if data_size >= self.first_number and data_size <= self.second_number:
                    return True

            if self.operator == ">":
                if data_size > self.first_number:
                    return True

            if self.operator == "<":
                if data_size < self.first_number:
                    return True

            if self.operator == "=":
                if data_size == self.first_number:
                    return True

        return False

    def import_param(self, param_str):
        """ Return True if import is successful  """
        param_groups = None
        """ Initial param cosmetic adjustment  """
        # re.sub(r"\s+", "", param, flags=re.UNICODE)  #  Removes all white spaces
        param_str = param_str.strip()

        """ Cherck the param syntax """
        for key, pattern in self.patterns.items():
            param_groups = re.findall(pattern, param_str)
            if param_groups:
                # Range
                if len(param_groups[0]) == 3:
                    self.first_number = int(param_groups[0][0])
                    self.operator = param_groups[0][1]
                    self.second_number = int(param_groups[0][2])
                else:
                    # Other equality, inequality
                    self.operator = param_groups[0][0]
                    self.first_number = int(param_groups[0][1])

                return True

        return False

