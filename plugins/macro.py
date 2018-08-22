"""
References:

https://outflank.nl/blog/2018/01/16/hunting-for-evil-detect-macros-being-executed/
http://az4n6.blogspot.com/2016/02/more-on-trust-records-macros-and.html

"""


import argparse
import urllib.parse as ul
from md.parser import *

"""
TO DO:

"""


class macro(object):
    name = "macro"

    """ Baseline params """
    compare_fields = ["key_path", "value_name", "value_content"]

    """ Constants and global declarations: """
    QUERY_VALUE_LIST = []

    QUERY_KEY_LIST = [
        r"Software\Microsoft\Office\11.0\Word\Security\Trusted Documents\TrustRecords",
        r"Software\Microsoft\Office\12.0\Word\Security\Trusted Documents\TrustRecords",
        r"Software\Microsoft\Office\14.0\Word\Security\Trusted Documents\TrustRecords",
        r"Software\Microsoft\Office\15.0\Word\Security\Trusted Documents\TrustRecords",
        r"Software\Microsoft\Office\16.0\Word\Security\Trusted Documents\TrustRecords",
        r"Software\Microsoft\Office\11.0\Excel\Security\Trusted Documents\TrustRecords",
        r"Software\Microsoft\Office\12.0\Excel\Security\Trusted Documents\TrustRecords",
        r"Software\Microsoft\Office\14.0\Excel\Security\Trusted Documents\TrustRecords",
        r"Software\Microsoft\Office\15.0\Excel\Security\Trusted Documents\TrustRecords",
        r"Software\Microsoft\Office\16.0\Excel\Security\Trusted Documents\TrustRecords",
        r"Software\Microsoft\Office\11.0\PowerPoint\Security\Trusted Documents\TrustRecords",
        r"Software\Microsoft\Office\12.0\PowerPoint\Security\Trusted Documents\TrustRecords",
        r"Software\Microsoft\Office\14.0\PowerPoint\Security\Trusted Documents\TrustRecords",
        r"Software\Microsoft\Office\15.0\PowerPoint\Security\Trusted Documents\TrustRecords",
        r"Software\Microsoft\Office\16.0\PowerPoint\Security\Trusted Documents\TrustRecords",
        r"Software\Microsoft\Office\11.0\Publisher\Security\Trusted Documents\TrustRecords",
        r"Software\Microsoft\Office\12.0\Publisher\Security\Trusted Documents\TrustRecords",
        r"Software\Microsoft\Office\14.0\Publisher\Security\Trusted Documents\TrustRecords",
        r"Software\Microsoft\Office\15.0\Publisher\Security\Trusted Documents\TrustRecords",
        r"Software\Microsoft\Office\16.0\Publisher\Security\Trusted Documents\TrustRecords",
        r"Software\Microsoft\Office\11.0\Access\Security\Trusted Documents\TrustRecords",
        r"Software\Microsoft\Office\12.0\Access\Security\Trusted Documents\TrustRecords",
        r"Software\Microsoft\Office\14.0\Access\Security\Trusted Documents\TrustRecords",
        r"Software\Microsoft\Office\15.0\Access\Security\Trusted Documents\TrustRecords",
        r"Software\Microsoft\Office\16.0\Access\Security\Trusted Documents\TrustRecords"
    ]

    def __init__(self, plugin, regparser):

        _parser = argparse.ArgumentParser(description='Plugin: "macro" designed to print information about macro-enabled documents executed on the host',
                                          usage=argparse.SUPPRESS)
        _parser.add_argument("-d", "--disable-baseline",
                             help="Would stop loading default baseline file: baseline/services.bl", default=True,
                             action="store_false", dest='baseline_enabled')
        _parser.add_argument("-f", "--baseline-file", help="Specify custom baseline location",
                             default="baseline/macro.bl", action="store", dest='baseline_file')

        _args = _parser.parse_args(args=plugin.args[1:])

        self.objects_matched = []
        self.plugin = plugin
        self.regparser = regparser
        self.args = _args
        self.baseline = None
        self.baseline_enabled = _args.baseline_enabled

        if self.baseline_enabled:
            self.baseline_file = _args.baseline_file
            """ Load the base line file """
            self.baseline = baseline(self.baseline_file, self.compare_fields)

    # The code taken from: https://github.com/DidierStevens/DidierStevensSuite/blob/master/oledump.py
    def ExtractStringsUNICODE(self, data):
        """
        - Fix the issue with printing results from the plugin:

        The code causing the issue from python registry:
            if self.has_ascii_name():
                return unpacked_string.decode("windows-1252")
            return unpacked_string.decode("utf-16le")

        Windows prints the utf-16le but not the Mac!
        """

        REGEX_STANDARD = '[\x09\x20-\x7E]'
        regex = '((' + REGEX_STANDARD + '\x00){%d,})'
        return [foundunicodestring.replace('\x00', '') for foundunicodestring, dummy in re.findall(regex % 4, data)]


    def _unescape(self, data):

        if data:
            _str = ul.unquote_plus(data)

            _str.replace(r'%20', r' ')
            return _str
        else:
            return ""

    def format_data(self, _item_fields):
        """ Adjust _item_fields - from parser._print_item """

        """ 
            The code causing the issue from python registry:
                if self.has_ascii_name():
                    return unpacked_string.decode("windows-1252")
                return unpacked_string.decode("utf-16le")
            
            Windows prints the utf-16le but not the Mac!
        """
        value_name = _item_fields.get('value_name', None)
        value_content = _item_fields.get('value_content', None)

        if value_name:
            unicode_str = self.ExtractStringsUNICODE(value_name)

            if unicode_str:
                unicode_str = "".join(unicode_str)
                unicode_str = self._unescape(unicode_str)
                _item_fields['value_name'] = unicode_str
            else:
                value_name = self._unescape(value_name)
                _item_fields['value_name'] = value_name

        if value_content:
            if value_content.endswith(b'\xff\xff\xff\x7f'):
                _item_fields["special"] = "Macro executed"
            else:
                _item_fields["special"] = "Macro not executed"

        return _item_fields

    def pull_data(self, keys, values, registry_hive):

        objects_matched = []

        self.regparser.debug_print(f'INFO: Pulling registry data ...')
        #objects_matched.extend(self.regparser.query_value_wd(registry_hive.file_path, values, registry_hive, True))
        objects_matched.extend(self.regparser.query_key(registry_hive.file_path, keys, registry_hive, True))

        return objects_matched

    def process_data(self, item):
        """ Parses the input data item, match against baseline and string format etc. """

        """ The data is a list of dictionaries """
        if isinstance(item, list):
            """ Navigate trough every element of the list """
            for entry in item:
                values = entry.get("values", None)

                """ The entry has values"""
                if values:
                    for _value in values:
                        if self._process_item(entry["key"], _value):
                            self.objects_matched.append(
                                {"hive": entry["hive"], "key": entry["key"], "values": _value, "plugin": self})
                else:
                    """ Process the key data only """
                    if self._process_item(entry["key"]):
                        self.objects_matched.append(
                            {"hive": entry["hive"], "key": entry["key"], "values": None, "plugin": self})

        else:
            """ Assume the data is a dictionary """
            values = item.get("values", None)

            """ The entry has values"""
            if values:
                for _value in values:
                    if self._process_item(item["key"], _value):
                        self.objects_matched.append(
                            {"hive": item["hive"], "key": item["key"], "values": _value, "plugin": self})
            else:
                """ Process the key data only """
                if self._process_item(item["key"]):
                    self.objects_matched.append(
                        {"hive": item["hive"], "key": item["key"], "values": None, "plugin": self})

    def _process_item(self, key, value=None):
        """ Return registry value according to plugin mode  """

        """ Remove the hive root """
        _root, _, _key_path = key.path().partition("\\")
        # _root, _, _key_path = _key_path.partition("\\")  # Removes ControlSetXXX string

        # Debug:
        if r"Microsoft\NetSh" in _key_path:
            test = ""

        """ Check item type """
        if value:
            _value_name = value.name()
            try:
                _value_content = value.value()
            except UnicodeError:
                _value_content = "regparser - UnicodeError"
                print(f'ERROR: RegistryValue.__init__ -> {_key_path}\\{_value_name}')

            item = {"type": "VALUE", "key_path": _key_path, "value_name": _value_name, "value_content": _value_content,
                    "temp_entry": True}
            item = self.format_data(item)
            item["value_content"] = str(item["value_content"])
        else:
            item = {"type": "KEY", "key_path": _key_path, "value_name": "", "value_content": "", "temp_entry": True}
            item = self.format_data(item)

        if self.baseline:
            if self.baseline.isfound(item):
                return None
            else:
                return item
        else:
            return item

        test = ""

    def execute(self):

        objects_matched = []

        if self.baseline_enabled:
            if self.baseline.initialized:
                self.regparser.debug_print(f'INFO: Baseline file: {self.baseline.file}')
                self.regparser.debug_print(f'INFO: Baseline items count: {len(self.baseline.items)}')
            else:
                self.regparser.debug_print(f'WARNING: Baseline not enabled')

        """ Parse all specified hive files """
        for hive_file in self.regparser.input_files:
            registry_hive = self.regparser._load_hive(hive_file)
            if not registry_hive:
                continue

            if registry_hive.hive_type.name != "NTUSER":
                self.regparser.debug_print('INFO: Unsupported hive type: "%s". '
                                           'Switch to the next hive' % registry_hive.hive_type.name)
                continue

            """ Pull registry data """
            objects_matched.extend(self.pull_data(self.QUERY_KEY_LIST, self.QUERY_VALUE_LIST, registry_hive))

        """ Parse data """
        for item in objects_matched:
            if item:
                self.process_data(item)

        """ Print all """
        self.regparser.objects_matched.extend(self.objects_matched)
        self.regparser.debug_print(
            f'INFO: Printing results (count: {len(self.regparser.objects_matched.items)})...')
        self.regparser.print_items()

        """ Export matched registry keys/values to .reg file, if export was enabled """
        if self.regparser.search_criteria.export_file:
            self.regparser.debug_print(f'INFO: Exporting macro data ...')
            self.regparser.export_items()
        else:
            if self.regparser.search_criteria.export_folder:
                self.regparser.debug_print(f'INFO: Exporting macro data ...')
                self.regparser.export_items()

        self.regparser.objects_matched.clear()
