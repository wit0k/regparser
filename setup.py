import sys
import os
import ctypes
import subprocess

program_name = "regparser"
required_python_ver = (3,6,0)
current_python_version = sys.version_info

pip_proxy_str = '--proxy http://30.207.31.50:8080'
required_dependencies = [
    'install --upgrade python-dateutil',
    'install --upgrade enum34',
    'install --upgrade unicodecsv',
    'install --upgrade https://github.com/williballenthin/python-registry/archive/master.zip'
]

def pip_install(cmd, via_proxy=True):

    if via_proxy:
        cmd = "pip " + pip_proxy_str + " " + cmd
        print(" - Execute: pip %s" % (cmd))
        subprocess.call(cmd, shell=True)
    else:
        cmd = "pip " + cmd
        print(" - Execute: pip %s" % (cmd))
        subprocess.call(cmd, shell=True)

print("Installing %s..." % (program_name))
print("Checking dependencies:")

try:
    is_admin = (os.getuid() == 0)
except AttributeError:
    is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0

if is_admin:
    print(" - Checking process privileges... [OK]")
else:
    print(" - Checking process privileges... [FAILED]")
    sys.exit(-1)

if current_python_version[0] == required_python_ver[0] and current_python_version[1] >= required_python_ver[1] and current_python_version[2] >= required_python_ver[2]:
    print(" - Checking Python version... [OK]")
else:
    print(" - Checking Python version... [FAILED]")
    print("     ERROR: Unsupported Python version: %s.%s.%s"% (current_python_version[0], current_python_version[1], current_python_version[2]))
    print("     Supported version: >= %s.%s.%s You can download it from: https://www.python.org/downloads/" % (required_python_ver[0], required_python_ver[1], required_python_ver[2]))
    print("     Execute the script again after successful installation. ")
    sys.exit(-1)

print("Installing packages...")

for cmd in required_dependencies:
    pip_install(cmd)

print("Done!")
