__author__ = "Witold Lawacz (wit0k)"
__version__ = '0.9.2'
__released__ = "20.04.2018"

import argparse
import sys
import time

from md.parser import *
from md.settings import *
from md.pluginmgr import plugin_manager

def main(argv):
    argsparser = argparse.ArgumentParser(usage=argparse.SUPPRESS,
                                         description='Registry hive parser...')

    """     -------------------------------------   Argument groups  ---------------------------------     """
    script_args = argsparser.add_argument_group('Script arguments', "\n")
    query_args = argsparser.add_argument_group('Query arguments', "\n")
    search_args = argsparser.add_argument_group('Search arguments', "\n")
    output_args = argsparser.add_argument_group('Output arguments', "\n")
    plugin_args = argsparser.add_argument_group('Plugin arguments', "\n")

    """     -------------------------------------   Script arguments ---------------------------------     """
    script_args.add_argument("-s", "--source", type=str, action='store', dest='input_folder', required=True,
                             help="File/Folder with offline registry hive(s) to parse [raw or .zip format supported]")
    script_args.add_argument("-r", "--recursive", action='store_true', dest='recursive', required=False,
                             help="Enables recursive search for --source folder")
    script_args.add_argument("-c", "--case-sensitive", action='store_true', dest='case_sensitive', required=False,
                             default=False, help="Enables case sensitive search (Default: case-insensitive")
    script_args.add_argument("-v", "--verbose", action='store_true', dest='debug_enabled', required=False, default=False,
                             help="Sends verbose debug data to stdout (Used for debugging)")

    """     -------------------------------------   Query arguments ---------------------------------     """
    query_args.add_argument("-qk", "--query-key", action='store', dest='query_key', required=False, help=r'Query given comma separated registry keys, example: -qk "Software\\Microsoft\\Windows\\CurrentVersion\\Run" (all registry values from queried key(s) would be printed)')
    query_args.add_argument("-qv", "--query-value", action='store', dest='query_value', required=False, help=r'Query given comma separated registry values, example: -qv "Software\\Microsoft\\Windows\\CurrentVersion\\Run\\ctfmon.exe" (only the queried value would be printed)')
    query_args.add_argument("-qs", "--query-subkeys", action='store_true', dest='query_subkeys', required=False,
                            default=False, help=r'Display root sub keys of given registry hive (Default: False)')

    """     -------------------------------------   Search arguments ---------------------------------     """
    search_args.add_argument("-tm", "--time-modified-string", action='store', dest='key_modified', required=False,
                             help=r'Comma separated regex date patterns: -tm "2014-09-04 09:50","2013|2014" would search for all keys modified in 2014-09-04 at 09:50 and on 2013 or 2014')

    search_args.add_argument("-td", "--time-modified-datetime", action='store', dest='key_modified_dt', required=False,
                             help=r'Comma separated Date time patterns: [datetime]..[datetime] or [Operator][datetime], where opertor is one of: ">", "<". Example: -td "2014-09-04 13:12:19..2014-09-04 13:12:25.703125",">2014-09-04"')
    search_args.add_argument("-ks", "--key-string", action='store', dest='key_string', required=False,
                             help=r'A string value, example: -ks "\\Run" would search for all keys having given string anywhere in their key path string')
    search_args.add_argument("-kr", "--key-regex", action='store', dest='key_regex', required=False,
                             help=r'A regex string, example: -kr "\\\\Run$" would search for all keys which ends with "\Run" string')
    search_args.add_argument("-kb", "--key-bin", action='store', dest='key_bin', required=False,
                             help=r'A binary value expressed in UTF8 escaped hex string, example: -kb "\\x5C\\x52\\x75\\x6E" would search for all keys having given sequence of bytes anywhere their key path bytes')
    search_args.add_argument("-vs", "--value-string", action='store', dest='value_string', required=False,
                             help=r'A string value, example: -vs "ctfmon" would search for all values having given string anywhere in their value name')
    search_args.add_argument("-vr", "--value-regex", action='store', dest='value_regex', required=False,
                             help=r'A regex string, example: -vr "ctfmon\.exe$" would search for value name which ends with "ctfmon.exe" string')
    search_args.add_argument("-vb", "--value-bin", action='store', dest='value_bin', required=False,
                             help=r'A binary value expressed in UTF8 escaped hex string, example: -vb "\\x63\\x74\\x66\\x6D\\x6F\\x6E" would search for all values having given sequence of bytes anywhere their name bytes')
    search_args.add_argument("-ds", "--data-string", action='store', dest='data_string', required=False,
                             help=r'A string value, example: -ds "CTF" would search for all values having given string anywhere in their data value')
    search_args.add_argument("-dr", "--data-regex", action='store', dest='data_regex', required=False,
                             help=r'A regex string, example: -dr "^CTF" would search for all values which starts with "CTF" string')
    search_args.add_argument("-db", "--data-bin", action='store', dest='data_bin', required=False,
                             help=r'A binary value expressed in UTF8 escaped hex string, example: -db "\\x43\\x54\\x46" would search for all values having given sequence of bytes anywhere their data bytes')
    search_args.add_argument("-dl", "--data-size", action='store', dest='data_size', required=False,
                             help=r'Comma separated Data size patterns: [int]..[int] or [Operator][int], where operator is one of: ">", "<" or "=". Example: -dl "3000..3225","=3226"')

    """     -------------------------------------   Output arguments ---------------------------------     """
    output_args.add_argument("-b", "--baseline-output", action='store_true', dest='sql_format', required=False, default=False,
                             help="Output to SQLite3 format (Used for baseline)")
    output_args.add_argument("-o", "--output-file", type=str, action='store', dest='output_file', required=False,
                             default="", help=r'Filepath to output file (Default: stdout)')

    output_args.add_argument("-a", "--output-format-all", action='store_true', dest='output_format_all', required=False,
                             default=False, help=r'Output all format fields [Time consuming task]')

    output_args.add_argument("-e", "--export-registry-folder", action='store', dest='export_folder', required=False,
                             default="", help='Folder path for exported .reg files')
    output_args.add_argument("-E", "--export-registry-file", action='store', dest='export_file', required=False,
                             default="", help='File path for exported single .reg file')
    output_args.add_argument("-f", "--output-format", action='store', dest='output_format', required=False,
                             default=r"plugin_name,hive_name,key_timestamp,special,key_subkeys,key_values,key_path,value_name,value_content", help=r'Format of output data: field,field,field')
    output_args.add_argument("-d", "--output-delimiter", action='store', dest='field_delimiter', required=False,
                             default=",", help=r'Used to separate the output fields (Default: ","')

    """     -------------------------------------   Plugins arguments ---------------------------------     """
    plugin_args.add_argument("-p", "--plugins", action='store', dest='plugins_to_execute', required=False,
                             help=r'Specify plugins to run with their parameters: ["autoruns -d","services"')

    args = argsparser.parse_args()
    argc = argv.__len__()

    if args.debug_enabled:
        print(f'\n{time.strftime("%Y-%m-%d %H:%M:%S")} INFO: Starting regparser ...')

    regparser = parser(args)

    if not regparser.initialized:
        print(f"ERROR: ERROR_PARSER_NOT_INITIALIZED [{ERROR_PARSER_NOT_INITIALIZED}]")
        sys.exit(ERROR_PARSER_NOT_INITIALIZED)

    """ Execute specified plugins only """
    if regparser.search_criteria.plugins_to_execute:
        pmgr = plugin_manager(regparser)

        """ Parse plugin parameters """
        for plugin_name in regparser.search_criteria.plugins_to_execute:
            _plugin = pmgr.load(plugin_name)
            """ Finally, execute only installed plugins, marked for execution """
            if _plugin._obj:
                regparser.loaded_plugins.append(_plugin)
                regparser.debug_print(f'INFO: Running: {_plugin.full_name()}')
                _plugin.execute(regparser)
    else:
        # Execute the parser with given parameters.
        regparser.execute()

    regparser.debug_print(f'Stopping regparser ...')

if __name__ == "__main__":
    main(sys.argv)

