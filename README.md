# RegParser ver. 0.5.0 [BETA]

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


