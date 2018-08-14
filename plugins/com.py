# https://github.com/retbandit/BlackHat2017/blob/master/eu-17-Thompson-Red-Team-Techniques-for-Evading-Bypassing-and-Disabling-MS-Advanced-Threat-Protection-and-Advanced-Threat-Analytics.pptx

"""
The tool takes following registry hives as input:
- UsrClass.dat <- HKEY_CURRENT_USER\Software\Classes

TO DO:
- http://www.hexacorn.com/blog/2018/04/23/beyond-good-ol-run-key-part-77/

"""
import argparse
import logging

from md.plugin import plugin
from md.parser import *

logger = logging.getLogger('plugin')

class com(plugin):

    name = "com"

    """ Baseline params """
    compare_fields = ["key_path", "value_name", "value_content"]

    def __init__(self, plugin, regparser):

        _parser = argparse.ArgumentParser(description='Plugin: %s designed to ...' % self.name, usage=argparse.SUPPRESS)
        _parser.add_argument("-d", "--disable-baseline", help="Would stop loading default baseline file: baseline/com.bl", default=True,
                             action="store_false", dest='baseline_enabled')
        _parser.add_argument("-f", "--baseline-file", help="Specify custom baseline location",
                             default="baseline/com.bl", action="store", dest='baseline_file')

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


    def execute(self):

        print('Execute plugin: "%s"' % self.name)

        """ Parse all specified hive files """
        for hive_file in self.regparser.input_files:
            registry_hive = self.regparser._load_hive(hive_file)

            if not registry_hive:
                continue

            if not registry_hive.hive_type.name == 'USRCLASS':
                logger.warning('Unsupported hive: %s' % hive_file)
                continue

            """ Find all CLSIDs with a ket ScriptletURL """
            scriptlet = 'ScriptletURL'.lower()
            treatas = 'TreatAs'.lower()
            inprocserver32 = 'InprocServer32'.lower()
            progid = "ProgID".lower()
            clsids = registry_hive.reg.open(r"CLSID")


            """ Iterate trough all COM Classes, IF one with ScriptletURL found, output associated items  """
            for _clsid in clsids.subkeys():

                scriptlet_found = False
                ProgID = ""
                TreatAs = ""
                CLSID = ""

                for subkey in _clsid.subkeys():

                    # Case ScriptletURL found
                    if scriptlet in subkey.name().lower():
                        self.objects_matched.append(
                            {"hive": registry_hive, "key": subkey, "values": subkey.values(), "plugin": self})
                        scriptlet_found = True

                    if (scriptlet_found) and (inprocserver32 in subkey.name().lower()):
                        self.objects_matched.append(
                                {"hive": registry_hive, "key": subkey, "values": subkey.values(), "plugin": self})

                    if (scriptlet_found) and (treatas in subkey.name().lower()):
                        self.objects_matched.append(
                                {"hive": registry_hive, "key": subkey, "values": subkey.values(), "plugin": self})

                        try:
                            TreatAs = subkey.value('(default)')
                        except Exception as msg:
                            pass

                    if (scriptlet_found) and (progid in subkey.name().lower()):
                        self.objects_matched.append(
                                {"hive": registry_hive, "key": subkey, "values": subkey.values(), "plugin": self})

                        try:
                            ProgID = subkey.value('(default)')
                        except Exception as msg:
                            pass

                    # Pull the ProgID\CLSID\(default)
                    if ProgID:
                        try:
                            malcious_clsid_key = registry_hive.reg.open(f"{ProgID}\CLSID")
                            malcious_clsid = malcious_clsid_key.value('(default)')
                            self.objects_matched.append(
                                {"hive": registry_hive, "key": malcious_clsid_key, "values": [malcious_clsid], "plugin": self})

                        except Exception as msg:
                            pass





            self.regparser.objects_matched.extend(self.objects_matched)
            self.regparser.debug_print(
                f'INFO: Printing results (count: {len(self.regparser.objects_matched.items)})...')
            self.regparser.print_items()










