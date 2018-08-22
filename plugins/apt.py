"""
References:

https://outflank.nl/blog/2018/01/16/hunting-for-evil-detect-macros-being-executed/
http://az4n6.blogspot.com/2016/02/more-on-trust-records-macros-and.html

"""


import argparse
from md.parser import *

"""
TO DO:
- http://www.hexacorn.com/blog/2016/11/24/beyond-good-ol-run-key-part-51/
- http://www.hexacorn.com/blog/2018/08/17/beyond-good-ol-run-key-part-84/

"""


class apt(object):
    name = "apt"

    """ Baseline params """
    compare_fields = ["key_path", "value_name", "value_content"]

    """ Constants and global declarations: """

    REG_VALUE_RULES = {
        '#1': {
            'hive_type': 'SOFTWARE',
            'value_name_path': 'Microsoft\Windows Script Host\Settings\Remote',
            'shall_exist': False,
            'expected_value_content': None,
            'reference': 'https://bit.ly/2Ppcu3d',  # http://www.hexacorn.com/blog/2018/08/18/lateral-movement-using-wshcontroller-wshremote-objects-iwshcontroller-and-iwshremote-interfaces/
            'decoder': None,
            'action': {'name': 'query_keys', 'items': [
                r'Classes\CLSID\{6F201542-B482-11D2-A250-00104BD35090}\*',
                r'Classes\Interface\{6F201541-B482-11D2-A250-00104BD35090}\*',
                r'Classes\Interface\{83EA33C0-CD14-11D2-A252-00104BD35090}\*',
                r'Classes\Interface\{8A9EA2C0-D348-11D2-A253-00104BD35090}\*',
                r'Classes\TypeLib\{6F201540-B482-11D2-A250-00104BD35090}\*',
                r'Classes\WSHRemote\*']}
        }

    }

    def __init__(self, plugin, regparser):

        _parser = argparse.ArgumentParser(description='Plugin: "apt" designed to print information about suspicious registry entires',
                                          usage=argparse.SUPPRESS)

        _args = _parser.parse_args(args=plugin.args[1:])

        self.objects_matched = []
        self.plugin = plugin
        self.regparser = regparser
        self.args = _args
        self.baseline_enabled = False

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

    def format_data(self, _item_fields, special=None):
        """ Adjust _item_fields - from parser._print_item """

        if special:
            _item_fields["special"] = special

        return _item_fields


    def execute(self):

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

            """ Pull registry data """
            for vrule_id, vrule in self.REG_VALUE_RULES.items():

                message = []
                message_str = []
                action = None
                key_value_str = vrule.get('value_name_path', None)

                hive_type = vrule.get('hive_type', None)

                # Apply the rule match only to supported hive types ...
                if hive_type:
                    if hive_type != registry_hive.hive_type.name:
                        self.regparser.debug_print('INFO: Rule: %s - Unsupported hive type: "%s". '
                                                   'Switch to the next rule' % (vrule_id, registry_hive.hive_type.name))
                        continue

                shall_exist = vrule.get('shall_exist', None)
                expected_value_content = vrule.get('expected_value_content', None)
                reference = vrule.get('reference', None)
                action = vrule.get('action', None)

                reg_entry = self.regparser.query_value_wd(hive_file=registry_hive.file_path, key_value_strings=[key_value_str],
                                              registry_hive=registry_hive, return_result=True)

                try:
                    reg_entry = reg_entry[0][0]
                except IndexError:
                    reg_entry = None

                if reg_entry is None:
                    value_name_exist = False
                    reg_item = None
                else:
                    # Case: The value exist
                    value_name_exist = True
                    reg_item = {"hive": reg_entry.get('hive'), "key": reg_entry.get('key'), "values": reg_entry.get('values', None), "plugin": self, 'special': ''}
                    reg_value = reg_item.get('values', None)

                    if reg_value:
                        reg_value = reg_value[0]
                        reg_value = reg_value.value()

                if shall_exist == True and value_name_exist == False:
                    message.append(f'The registry value shall exist, but was not found')
                    message.append('Reference: ' + reference)

                elif shall_exist == False and value_name_exist == True:
                    # Current design does not allow the printing of entries having NULL key objects ...
                    message.append(f'The registry value shall NOT exist, but was found')
                    message.append('Reference: ' + reference)

                elif shall_exist == False and value_name_exist == False:
                    continue

                elif shall_exist == True and value_name_exist == True:
                    if reg_value != expected_value_content:
                        message.append(f'Content mismatch: Expected value: {expected_value_content}')
                        message.append('Reference: ' + reference)

                if reg_item:
                    message.insert(0, vrule_id)
                    reg_item['special'] = " | ".join(message)
                    self.regparser.objects_matched.append(reg_item)

                if action:
                    if action.get('name', None) == 'query_keys':
                        keys = action.get('items', None)

                        if keys:
                            for key in keys:
                                key_entry = self.regparser.query_key(registry_hive.file_path, [key],
                                                                     registry_hive=registry_hive, return_result=True)
                                if key_entry is not [[]]:

                                    for _entry in key_entry:
                                        _entry['special'] = vrule_id
                                        _entry['plugin'] = self

                                    self.regparser.objects_matched.extend(key_entry)



        """ Print matched items """
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
