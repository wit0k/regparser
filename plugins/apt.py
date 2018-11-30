"""
References:

https://outflank.nl/blog/2018/01/16/hunting-for-evil-detect-macros-being-executed/
http://az4n6.blogspot.com/2016/02/more-on-trust-records-macros-and.html

"""


import argparse
from md.parser import *

"""
TO DO:
- Working on http://www.hexacorn.com/blog/2018/09/02/beyond-good-ol-run-key-part-86/

I worked out the correct registration process, but i am struggling to create a DLL with the right functions.

[HKEY_CLASSES_ROOT\CLSID\{D19F9331-3110-11D4-991C-005004D3B3DD}]
@="Cleaner for Windows Meta Data Files Handler"

[HKEY_CLASSES_ROOT\CLSID\{D19F9331-3110-11D4-991C-005004D3B3DD}\DefaultIcon]
@="C:\\Windows\\System32\\occache.dll,0"

[HKEY_CLASSES_ROOT\CLSID\{D19F9331-3110-11D4-991C-005004D3B3DD}\InProcServer32]
@="C:\\safe_dll\\disk_cleanup.dll"
"ThreadingModel"="Apartment"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Meta Data Files]
@="{D19F9331-3110-11D4-991C-005004D3B3DD}"
"AdvancedButtonText"="@C:\\Windows\\System32\\occache.dll,-1072"
"Priority"=hex:64,00,00,00
"Display"="Windows Meta Data Files"


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
            'author': 'wit0k',
            'description': 'Detects a possible Lateral movement technique via wscript.exe',
            'signature_category': 'Lateral movement',
            'hive_type': 'SOFTWARE',
            'value_name_path': 'Microsoft\Windows Script Host\Settings\Remote',
            'shall_exist': False,
            'expected_value_content': None,
            'reference': 'https://bit.ly/2Ppcu3d',  # http://www.hexacorn.com/blog/2018/08/18/lateral-movement-using-wshcontroller-wshremote-objects-iwshcontroller-and-iwshremote-interfaces/
            'value_content_decoder': None,
            'action': {'name': 'query_keys', 'items': [
                r'Classes\CLSID\{6F201542-B482-11D2-A250-00104BD35090}\*',
                r'Classes\Interface\{6F201541-B482-11D2-A250-00104BD35090}\*',
                r'Classes\Interface\{83EA33C0-CD14-11D2-A252-00104BD35090}\*',
                r'Classes\Interface\{8A9EA2C0-D348-11D2-A253-00104BD35090}\*',
                r'Classes\TypeLib\{6F201540-B482-11D2-A250-00104BD35090}\*',
                r'Classes\WSHRemote\*']}
        },
        '#2': {
            'author': 'wit0k',
            'description': 'Detects a possible Turla Outlook COM Hijack (No admin rights required)',
            'signature_category': 'COM Hijack',
            'hive_type': 'USRCLASS',
            'value_name_path': r'CLSID\{84DA0A92-25E0-11D3-B9F7-00C04F4C8F5D}\TreatAs',
            'shall_exist': False,
            'expected_value_content': None,
            'reference': 'https://bit.ly/2OXVTSP',  # https://www.welivesecurity.com/wp-content/uploads/2018/08/Eset-Turla-Outlook-Backdoor.pdf
            'value_content_decoder': None,
            'action': {'name': 'query_keys', 'items': [
                r'CLSID\{49CBB1C7-97D1-485A-9EC1-A26065633066}\*',
                r'CLSID\{84DA0A92-25E0-11D3-B9F7-00C04F4C8F5D}\*'
            ]}
        },
        '#3': {
            'author': 'wit0k',
            'description': 'Detects a possible Turla Outlook COM Hijack (Admin rights required)',
            'signature_category': 'COM Hijack',
            'hive_type': 'SOFTWARE',
            'value_name_path': r'Classes\CLSID\{84DA0A92-25E0-11D3-B9F7-00C04F4C8F5D}\TreatAs',
            'shall_exist': False,
            'expected_value_content': None,
            'reference': 'https://bit.ly/2OXVTSP',  # https://www.welivesecurity.com/wp-content/uploads/2018/08/Eset-Turla-Outlook-Backdoor.pdf
            'value_content_decoder': None,
            'action': {'name': 'query_keys', 'items': [
                r'Classes\CLSID\{49CBB1C7-97D1-485A-9EC1-A26065633066}\*',
                r'Classes\CLSID\{84DA0A92-25E0-11D3-B9F7-00C04F4C8F5D}\*'
            ]}
        },
        '#4': {
            'author': 'wit0k',
            'description': 'Detects Turla Virtual File system stored in the registry',
            'signature_category': 'Artifact',
            'hive_type': 'NTUSER',
            'value_name_path': r'Software\Microsoft\Windows\CurrentVersion\Settings\ZonePolicy',
            'shall_exist': False,
            'expected_value_content': None,
            'reference': 'https://bit.ly/2OXVTSP',  # https://www.welivesecurity.com/wp-content/uploads/2018/08/Eset-Turla-Outlook-Backdoor.pdf
            'value_content_decoder': None,
            'action': {'name': 'query_keys', 'items': [
                r'Software\Microsoft\Windows\CurrentVersion\Settings\ZonePolicy\*'
            ]}
        },
        '#5': {
            'author': 'wit0k',
            'description': 'Malicious Disk Cleanup handler',
            'signature_category': 'Persistence',
            'hive_type': 'SOFTWARE',
            'value_name_path': r'Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\*\CleanupString',
            'shall_exist': False,
            'expected_value_content': None,
            'reference': 'https://bit.ly/2wCu8b3',  # http://www.hexacorn.com/blog/2018/09/02/beyond-good-ol-run-key-part-86/, https://docs.microsoft.com/pl-pl/windows/desktop/lwef/disk-cleanup#registration
            'value_content_decoder': None,
            'action': [
                {'name': 'query_values', 'items': [r'(default)']},
                {'name': 'query_keys', 'items': []}
            ]
        },
        '#6': {
            'author': 'wit0k',
            'description': 'Malicious Disk Cleanup handler',
            'signature_category': 'Persistence',
            'hive_type': 'SOFTWARE',
            'value_name_path': r'Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\*\PreCleanupString',
            'shall_exist': False,
            'expected_value_content': None,
            'reference': 'https://bit.ly/2wCu8b3',  # http://www.hexacorn.com/blog/2018/09/02/beyond-good-ol-run-key-part-86/
            'value_content_decoder': None,
            'action': [
                {'name': 'query_values', 'items': [r'(default)']},
                {'name': 'query_keys', 'items': []}
            ]
        },
        '#7': {
            'author': 'wit0k',
            'description': 'Malicious Disk Cleanup handler',
            'signature_category': 'Persistence',
            'hive_type': 'SOFTWARE',
            'value_name_path': r'Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\*\Autorun',
            'shall_exist': False,
            'expected_value_content': None,
            'reference': 'https://bit.ly/2wCu8b3 ',  # http://www.hexacorn.com/blog/2018/09/02/beyond-good-ol-run-key-part-86/
            'value_content_decoder': None,
            'action': [
                {'name': 'query_values', 'items': [r'(default)']},
                {'name': 'query_keys', 'items': []}
            ]


        },
        '#8': {
            'author': 'wit0k',
            'description': 'Privilege Escalation',
            'signature_category': 'Elevation',
            'hive_type': 'NTUSER',
            'value_name_path': r'System\CurrentControlSet\*\ImagePath',
            'shall_exist': False,
            'expected_value_content': None,
            'reference': 'https://bit.ly/2tm2AVY ',  # https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/
            'value_content_decoder': None,
            'action': [
                {'name': 'query_values', 'items': [r'ImagePath']},
                {'name': 'query_keys', 'items': ['System\CurrentControlSet\*']}
            ]

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
                reg_entries = []
                reg_entry = None

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

                reg_entries = self.regparser.query_value_wd(hive_file=registry_hive.file_path, key_value_strings=[key_value_str],
                                              registry_hive=registry_hive, return_result=True)

                for reg_entry in reg_entries:
                    if reg_entry == []:
                        reg_entry = None
                    elif isinstance(reg_entry, list):
                        test = "we have a pb"
                        reg_entry = reg_entry[0]


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

                        current_key_path = reg_item['key'].path()
                        _, __, current_key_path = current_key_path.partition('\\')

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

                    action = vrule.get('action', None)
                    if action:
                        if isinstance(action, dict):
                            actions = [action]
                        else:
                            actions = action

                        for action in actions:

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

                            if action.get('name', None) == 'query_values':
                                values = action.get('items', None)

                                if values:
                                    for value in values:
                                        _key_value_str = "%s\\%s" % (current_key_path, value)
                                        value_entry = self.regparser.query_value_wd(hive_file=registry_hive.file_path,
                                                                                    key_value_strings=[_key_value_str],
                                                                                    registry_hive=registry_hive,
                                                                                    return_result=True)

                                        if value_entry != [[]]:
                                            for _entry in value_entry:
                                                if isinstance(_entry, list):
                                                    for child_entry in _entry:
                                                        child_entry['special'] = vrule_id
                                                        child_entry['plugin'] = self

                                                        self.regparser.objects_matched.append(child_entry)
                                                else:
                                                    _entry['special'] = vrule_id
                                                    _entry['plugin'] = self

                                                    self.regparser.objects_matched.extend(value_entry)

                    message = []
                    keys = []
                    action = None
                    reg_item = {}
                    _key_value_str = None


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
