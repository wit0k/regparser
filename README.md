# RegParser - 0.7.0 [BETA]

#### Description:

RegParser (rp) is a python wrapper script for python-registry framework (@williballenthin [FireEye]). This command-line utility is designed to slightly extend and facilitate framework’s capabilities. In general it’s used to parse any offline windows registry hives during malware hunting or forensic investigations.

It comes with following major features: 

* Search for a registry key, value name or value data patterns described by a comma separated: strings, regex strings or utf8 hex binary strings
* Search for value data by its size, specified by operators like range, equality or inequality
* Search for registry modified keys at given date and time, specified by regex string pattern or range, or inequality operators 
* Query the registry keys or values (including partial wildcard support)
* Enumerate and display hidden keys and values
* Hash registry value content
* Detect hive type
* Export results to .REG format (Simplifies malware analysis/infection reproduction based on file-less registry load points)
* Export results to SQLite (Used by regparser for plugin’s baseline)
* Export results to CSV or stout
* Customize output data (21 different format fields)
* Easy plugin implementation and support with built in plugins like “autoruns”,”services”
* Plugins baseline support 

Note: More details in **README.pdf**

#### Requirements:

* Python 3.6.1 Framework 
* Operating system:  Windows, Linux, MacOS
* python-registry module (1.2.0 at least):

In proxy enabled environment use: pip --proxy http://PROXY_IP:PORT install %package name% 

* pip install --upgrade python-dateutil
* pip install --upgrade enum34
* pip install --upgrade unicodecsv
* pip install --upgrade https://github.com/williballenthin/python-registry/archive/master.zip
* wget/save RegistryParser
* Unzip RegistryParser and run: python rp.py -h (To review all available commands)


#### Parameters
<pre>
optional arguments:
  -h, --help            show this help message and exit

Script arguments:

  -s INPUT_FOLDER, --source INPUT_FOLDER
                        File/Folder with offline registry hive(s) to parse
                        [raw or .zip format supported]
  -r, --recursive       Enables recursive search for --source folder
  -c, --case-sensitive  Enables case sensitive search (Default: case-
                        insensitive
  -v, --verbose         Sends verbose debug data to stdout (Used for
                        debugging)

Query arguments:

  -qk QUERY_KEY, --query-key QUERY_KEY
                        Query given comma separated registry keys, example:
                        -qk "Software\Microsoft\Windows\CurrentVersion\Run"
                        (all registry values from queried key(s) would be
                        printed)
  -qv QUERY_VALUE, --query-value QUERY_VALUE
                        Query given comma separated registry values, example:
                        -qv "Software\Microsoft\Windows\CurrentVersion\Run\ctf
                        mon.exe" (only the queried value would be printed)
  -qs, --query-subkeys  Display root sub keys of given registry hive (Default:
                        False)

Search arguments:

  -tm KEY_MODIFIED, --time-modified-string KEY_MODIFIED
                        Comma separated regex date patterns: -tm "2014-09-04
                        09:50",”2013|2014” would search for all keys modified
                        in 2014-09-04 at 09:50 and on 2013 or 2014
  -td KEY_MODIFIED_DT, --time-modified-datetime KEY_MODIFIED_DT
                        Comma separated Date time patterns:
                        [datetime]..[datetime] or [Operator][datetime], where
                        opertor is one of: ">", "<". Example: -td "2014-09-04
                        13:12:19..2014-09-04 13:12:25.703125",">2014-09-04"
  -ks KEY_STRING, --key-string KEY_STRING
                        A string value, example: -ks "\Run" would search for
                        all keys having given string anywhere in their key
                        path string
  -kr KEY_REGEX, --key-regex KEY_REGEX
                        A regex string, example: -kr "\\Run$" would search for
                        all keys which ends with "\Run" string
  -kb KEY_BIN, --key-bin KEY_BIN
                        A binary value expressed in UTF8 escaped hex string,
                        example: -kb "\x5C\x52\x75\x6E" would search for all
                        keys having given sequence of bytes anywhere their key
                        path bytes
  -vs VALUE_STRING, --value-string VALUE_STRING
                        A string value, example: -vs "ctfmon" would search for
                        all values having given string anywhere in their value
                        name
  -vr VALUE_REGEX, --value-regex VALUE_REGEX
                        A regex string, example: -vr "ctfmon\.exe$" would
                        search for value name which ends with "ctfmon.exe"
                        string
  -vb VALUE_BIN, --value-bin VALUE_BIN
                        A binary value expressed in UTF8 escaped hex string,
                        example: -vb "\x63\x74\x66\x6D\x6F\x6E" would search
                        for all values having given sequence of bytes anywhere
                        their name bytes
  -ds DATA_STRING, --data-string DATA_STRING
                        A string value, example: -ds "CTF" would search for
                        all values having given string anywhere in their data
                        value
  -dr DATA_REGEX, --data-regex DATA_REGEX
                        A regex string, example: -dr "^CTF" would search for
                        all values which starts with "CTF" string
  -db DATA_BIN, --data-bin DATA_BIN
                        A binary value expressed in UTF8 escaped hex string,
                        example: -db "\x43\x54\x46" would search for all
                        values having given sequence of bytes anywhere their
                        data bytes
  -dl DATA_SIZE, --data-size DATA_SIZE
                        Comma separated Data size patterns: [int]..[int] or
                        [Operator][int], where operator is one of: ">", "<" or
                        "=". Example: -dl "3000..3225","=3226"

Output arguments:

  -b, --baseline-output
                        Output to SQLite3 format (Used for baseline)
  -o OUTPUT_FILE, --output-file OUTPUT_FILE
                        Filepath to output file (Default: stdout)
  -a, --output-format-all
                        Output all format fields [Time consuming task]
  -e EXPORT_FOLDER, --export-registry-folder EXPORT_FOLDER
                        Folder path for exported .reg files
  -E EXPORT_FILE, --export-registry-file EXPORT_FILE
                        File path for exported single .reg file
  -f OUTPUT_FORMAT, --output-format OUTPUT_FORMAT
                        Format of output data: field,field,field
  -d FIELD_DELIMITER, --output-delimiter FIELD_DELIMITER
                        Used to separate the output fields (Default: ","

Plugin arguments:

  -p PLUGINS_TO_EXECUTE, --plugins PLUGINS_TO_EXECUTE
                        Specify plugins to run with their parameters:
                        ["autoruns -d","services"

</pre>

#### Examples

Following query would execute autoruns-like scan and enumerate services on all hives from the hives/ folder recursively. (Result would be printed into standard output)

<pre>rp.py -r -s hives -p autoruns,services</pre>


Following query would display immediate sub keys of every registry hive in “hives/ folder”. (This option ignores the output format specified by -f option)

<pre>rp.py -s hives -qs

Output :

hives/NTUSER.DAT,AppEvents
hives/NTUSER.DAT,Console
hives/NTUSER.DAT,Control Panel
hives/NTUSER.DAT,Environment
hives/NTUSER.DAT,Identities
hives/NTUSER.DAT,Keyboard Layout
hives/NTUSER.DAT,Printers
hives/NTUSER.DAT,Software
hives/NTUSER.DAT,UNICODE Program Groups
hives/NTUSER.DAT,Windows 3.1 Migration Status
</pre>


Following query looks for value named “StubPath” in every sub key of “…\Installed Components” key. (It demonstrates limited wildcard support)
<pre>
rp.py -s hives/sys_SOFTWARE.tmp -qv "Microsoft\Active Setup\Installed Components\*\StubPath"

Output (Shortened):

sys_SOFTWARE.tmp,,CMI-CreateHive{199DAFC2-6F16-4946-BF90-5A3FC3A60902}\Microsoft\Active Setup\Installed Components\{89B4C1CD-B018-4511-B0A1-5476DBF70820},StubPath,C:\Windows\system32\Rundll32.exe C:\Windows\system32\mscories.dll,Install
</pre>
Following query looks for all keys which end on “\Run” or “\RunOnce” (It demonstrates the regex support)
<pre>
rp.py -s hives/sys_SOFTWARE.tmp -kr "\\Run$","\\RunOnce$"

Output (Shortened):

sys_SOFTWARE.tmp,,CMI-CreateHive{199DAFC2-6F16-4946-BF90-5A3FC3A60902}\Classes\SDRun.AutoPlayHandler\shell\run,None,None
sys_SOFTWARE.tmp,,CMI-CreateHive{199DAFC2-6F16-4946-BF90-5A3FC3A60902}\Microsoft\Group Policy\Client\RunOnce,{ECDBB9F9-F918-4B9C-BCA5-BC7518869245},
sys_SOFTWARE.tmp,,CMI-CreateHive{199DAFC2-6F16-4946-BF90-5A3FC3A60902}\Microsoft\Windows\CurrentVersion\Run,IgfxTray,C:\Windows\system32\igfxtray.exe
sys_SOFTWARE.tmp,,CMI-CreateHive{199DAFC2-6F16-4946-BF90-5A3FC3A60902}\Wow6432Node\Microsoft\Windows\CurrentVersion\Run,IMSS,"C:\Program Files (x86)\Intel\Intel(R) Management Engine Components\IMSS\PIconStartup.exe"
</pre>

Following query demonstrates how to search for hidden value names containing a NULL byte (\x00). Thanks to -v option you may observe what’s the real binary search pattern. Additionally via -f option you may adjust the output format, this time we are especially interested in “value_name_unicode” so we can see the exact position of the NULL byte:
<pre>
rp.py -v -s hives/NTUSER-Trojan.Poweliks.dat -vb "\x00" -f "key_path,value_name_unicode,value_content"

Output (Shortened):

PARSER Started: 2017-08-13 13:21:21
WARNING: Binary arguments (-kb, -vb, -db) do not support case insensitive mode. Enabling cases-sensitive mode...
Loading hives from: hives/NTUSER-Trojan.Poweliks.dat
Hives:
- hives/NTUSER-Trojan.Poweliks.dat

Parameters:
- Export to: None
- Case sensitive: True

Search entries:
- { VALUE  |   BIN  |   b'\x00\x00' }

Load hive: hives/NTUSER-Trojan.Poweliks.dat
$$$PROTO.HIV\Software\Microsoft\Windows\CurrentVersion\Run,b'\x00\x00a\x00',rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write("\74script language=jscript.encode>…
</pre>


