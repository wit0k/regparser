import argparse

from md.parser import *
from md.baseline import *

"""

The registry key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet is a symbolic registry link, which points to a copy of current control set, which finally holds the current configuration of Windows Services loaded by Windows loader. 

The OS maintains several copies of control sets and stores them in the keys with following naming standard: HKEY_LOCAL_MACHINE\SYSTEM\ControlSetXXX (Where XXX is a set number like 001, 002 or 003). 
The key HKEY_LOCAL_MACHINE\SYSTEM\Select and its values determine the role of each control set respectively:

Current - If set to 1, the CurrentControlSet would point to ControlSet001 
Default – Unclear and untested. On the machine without a failure, seems to point to Current
Failed - Holds the set number for the last unsuccessful boot (By default 0, indicates no failure)
LastKnownGood - Holds the set number, for the last successful boot like ControlSet002

Ref: 
https://msdn.microsoft.com/en-us/library/bb742541.aspx
Windows Internals Book

Service types and startup modes taken form: https://github.com/tomchop/volatility-autoruns/blob/master/autoruns.py

"""

class services(object):

    """ Constants and global declarations: """
    name = "services"

    service_types = {
        0x001: "Kernel driver",
        0x002: "File system driver",
        0x004: "Arguments for adapter",
        0x008: "File system driver",
        0x010: "Own_Process",
        0x020: "Share_Process",
        0x100: "Interactive",
        0x110: "Interactive",
        0x120: "Share_process Interactive",
        -1: "Unknown",
    }
    service_startup = {
        0x00: "Boot Start",
        0x01: "System Start",
        0x02: "Auto Start",
        0x03: "Manual",
        0x04: "Disabled",
        -1: "Unknown",
    }
    lite_value_names = [
        r"DisplayName",
        r"FailureCommand",
        r"Start",
        r"Type",
        r"ImagePath",
        r"Description",
        r"Group",
        r"ServiceDll",
    ]
    services_roots = {
        1: r"ControlSet001\Services",
        2: r"ControlSet002\Services",
        3: r"ControlSet003\Services"
    }

    """ Baseline params """
    compare_fields = ["key_path", "value_name", "value_content"]

    def __init__(self, plugin, regparser):

        _parser = argparse.ArgumentParser(description='Plugin: "services" designed to query Windows Services. '
                                                      'REMARK: CurrentControlSet name is exposed via format field: "special"', usage=argparse.SUPPRESS)
        _parser.add_argument("-a", "--scann-all-controlsets",
                             help="Would scan all ControlSets (Time consuming)",
                             default=False, action="store_true", dest='scan_all_controlsets')
        _parser.add_argument("-v", "--scan-all-values", dest='scan_all_values',
                             help="Would scan all registry values (Time consuming)", default=False,
                             action="store_true")
        _parser.add_argument("-d", "--disable-baseline", help="Would stop loading default baseline file: baseline/services.bl", default=True,
                             action="store_false", dest='baseline_enabled')
        _parser.add_argument("-f", "--baseline-file", help="Specify custom baseline location",
                             default="baseline/services.bl", action="store", dest='baseline_file')
        _args = _parser.parse_args(args=plugin.args[1:])

        self.objects_matched = []
        self.plugin = plugin
        self.regparser = regparser
        self.args = _args
        self.scan_all_controlsets = _args.scan_all_controlsets
        self.scan_all_values = _args.scan_all_values
        self.baseline = None
        self.baseline_enabled = _args.baseline_enabled

        if self.baseline_enabled:
            self.baseline_file = _args.baseline_file

            """ Load the base line file """
            self.baseline = baseline(self.baseline_file, self.compare_fields)

    def format_data(self, _item_fields):
        """ Adjust _item_fields - from parser._print_item """
        field_dictionary = None

        if _item_fields:
            """ Adjust Start and Type value """
            if _item_fields["value_name"].upper() == "START":
                field_dictionary = self.service_startup

            """ Adjust Start value """
            if _item_fields["value_name"].upper() == "TYPE":
                field_dictionary = self.service_types

            if field_dictionary:
                try:
                    _service_startup = field_dictionary[_item_fields["value_content"]]
                    _service_startup = f" ({_service_startup})"
                except KeyError:
                    _service_startup = " (Unknown)"

                _item_fields["value_content"] = str(_item_fields["value_content"]) + _service_startup

            """ Remove the hive root """
            _tmp_entry = None
            try:
                if _item_fields["temp_entry"]:
                    _tmp_entry = True
            except KeyError:
                _tmp_entry = False

            try:
                if not _tmp_entry:
                    _root, _, _key_path = _item_fields["key_path"].partition("\\")  # Removes ControlSetXXX string
                    _item_fields["key_path"] = _key_path
                    _item_fields["special"] = _root
            except KeyError:
                pass

        return _item_fields

    def process_data(self, item):
        if isinstance(item["values"], list):
            if item["values"]:
                for _value in item["values"]:
                    _item = self._process_item(item["key"], _value)
                    if _item:
                        self.objects_matched.append(
                            {"hive": item["hive"], "key": item["key"], "values": _value, "plugin": self})
            else:
                if self._process_item(item["key"]):
                    self.objects_matched.append({"hive": item["hive"], "key": item["key"], "values": None, "plugin": self})

        else:
            if self._process_item(item["key"]):
                self.objects_matched.append(
                    {"hive": item["hive"], "key": item["key"], "values": item["values"], "plugin": self})

    def _process_item(self, key, value=None):
        """ Return registry value according to plugin mode  """

        """ Remove the hive root """
        _root, _, _key_path = key.path().partition("\\")
        _root, _, _key_path = _key_path.partition("\\")  # Removes ControlSetXXX string
        """ Check item type """
        if value:
            _value_name = value.name()
            try:
                _value_content = value.value()
            except UnicodeError:
                _value_content = "regparser - UnicodeError"
                print(f'ERROR: RegistryValue.__init__ -> {_key_path}\\{_value_name}')

            item = {"type": "VALUE", "key_path": _key_path, "value_name": _value_name, "value_content": _value_content, "temp_entry": True}
            item = self.format_data(item)
            item["value_content"] = str(item["value_content"])
        else:
            item = {"type": "KEY", "key_path": _key_path, "value_name": "", "value_content": "", "temp_entry": True}
            item = self.format_data(item)


        """ Check if Lite scan was specified """
        if not self.scan_all_values:
            """ Lite scan applies to registry values only """
            if item["type"] == "VALUE":
                if value.name() in self.lite_value_names:
                    if self.baseline:
                        if self.baseline.isfound(item):
                            return None
                        else:
                            return item
                    else:
                        return item
        else:
            if self.baseline:
                if self.baseline.isfound(item):
                    return None
                else:
                    return item
            else:
                return item

    def execute(self):

        if self.baseline_enabled:
            if self.baseline.initialized:
                self.regparser.debug_print(f'INFO: Baseline file: {self.baseline.file}')
                self.regparser.debug_print(f'INFO: Baseline items count: {len(self.baseline.items)}')
            else:
                self.regparser.debug_print(f'WARNING: Baseline not enabled')

        objects_matched = []

        """ Parse all specified hive files """
        for hive_file in self.regparser.input_files:
            registry_hive = self.regparser._load_hive(hive_file)
            if not registry_hive:
                continue

            # Follow only when SYSTEM hive was detected
            elif registry_hive.hive_type is not Registry.HiveType.SYSTEM:
                self.regparser.debug_print(f'WARNING: Skipping non-SYSTEM hive ...')
                continue

            """ Get Control Sets Info """
            self.regparser.debug_print(f'INFO: Getting CurrentSet info ...')
            key = registry_hive.reg.open("Select")
            values = []
            for _value in key.values():
                values.append(_value)
                self.regparser.debug_print(f'INFO: - {_value.name()}: {_value.value()}')
            self.objects_matched.append(
                {"hive": registry_hive, "key": key, "values": values, "plugin": self})

            """ Get the Current set """
            self.regparser.debug_print(f'INFO: Getting CurrentControlSet ...')
            try:
                CurrentControlSet = self.services_roots[key.value("Current").value()]
            except Exception:
                self.regparser.debug_print(f'ERROR: Plugin: {self.name} -> Unable to determine CurrentControlSet')
                CurrentControlSet = None
            self.regparser.debug_print(f'INFO: - CurrentControlSet: {CurrentControlSet}')

            """ Modify services_roots accordingly """
            if CurrentControlSet and not self.scan_all_controlsets:
                self.services_roots.clear()
                self.services_roots[0] = CurrentControlSet

            """ Enumerate every service root/set """
            self.regparser.debug_print(f'INFO: Enumerating Services sets ...')
            for _service_root in self.services_roots.values():
                try:
                    _services_key = registry_hive.reg.open(_service_root)
                except Registry.RegistryKeyNotFoundException:
                    self.regparser .debug_print(
                        f'{registry_hive.file_path} -> {_service_root}: "ERROR_PARSER_KEY_NOT_FOUND')
                    continue

                self.regparser.debug_print(f'INFO: Pulling registry data ...')
                self.regparser.debug_print(f'INFO: Service root: {_service_root}')
                """ Retrieve registry data for all services """
                self.regparser.query_key_recursive(registry_hive, _services_key, objects_matched)
                self.regparser.debug_print(f'INFO: - Data items: {len(objects_matched)}')

                self.regparser.debug_print(f'INFO: Parsing services data ...')
                """ Adjust and parse registry data """
                if objects_matched:
                    for reg_item in objects_matched:
                        self.process_data(reg_item)

        """ Print all """
        self.regparser.objects_matched.extend(self.objects_matched)
        self.regparser.debug_print(f'INFO: Printing results (count: {len(self.regparser.objects_matched.items)})...')
        self.regparser.print_items()

        """ Export matched registry keys/values to .reg file, if export was enabled """
        if self.regparser.search_criteria.export_file:
            self.regparser.debug_print(f'INFO: Exporting services ...')
            self.regparser.export_items()
        else:
            if self.regparser.search_criteria.export_folder:
                self.regparser.debug_print(f'INFO: Exporting services ...')
                self.regparser.export_items()

        self.regparser.objects_matched.clear()

