#! /usr/bin/python
import json
import subprocess
import os
import re

from conf.config import VOLATILITY_PATH
from lib.common.utils import get_workdir_path
from lib.core.database import DataBaseConnection


def create_golden_image(machine_instance):
    pass


def run_extractor(memory_instance, malware_sample,machine_instance=None):
    command = VOLATILITY_PATH + ' --profile ' + machine_instance.memory_profile + ' -f "' + machine_instance.get_memory_path() + '" apihooks'
    proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)



    hook_data = []

    disasm_code_started = False
    whitelisted_patch = False
    in_patch_disassembly = False
    hook_code = ""
    export = ""
    module = ""
    process = ""
    hook_mode = ""
    hook_type = ""
    hooking_module = ""
    count = 0
    hooks_count = 0

    # Define whitelist
    whitelist = ["IEFRAME.dll", "adsldpc.dll", "glib-2.0.dll", "MSVCR120.dll", "RPCRT4.dll"]

    original_apihooks = open(os.path.join(get_workdir_path(malware_sample),'original.apihooks'), 'w+')

    for line in iter(proc.stdout.readline, ''):
        # print line
        original_apihooks.write(line)
        mode_matches = False
        p = re.compile('Hook mode: (.+)')
        t = p.match(line)
        if t:
            hook_mode = t.group(1)
            # print 'Hook mode: ' + hook_mode
            # Usermode or Kernelmode

        # Get hook type
        p = re.compile('Hook type: (.+)')
        t = p.match(line)
        if t:
            hook_type = t.group(1)
            # print 'Hook Type: ' + hook_type
            # NT Syscall or Inline/Trampoline or Import Address Table (IAT)

        # Get proccess name
        if hook_mode == "Usermode":
            p = re.compile('Process: \d+ \((.+)\)')
            t = p.match(line)
            if t:
                process = t.group(1)
                # print 'process_name:' + process

        # Find the hook function, and hooked module
        if hook_mode == "Usermode":
            if (hook_type == "NT Syscall"):
                p = re.compile('Function: (.+)')
                t = p.match(line)
                if t:
                    module = t.group(1)
                    export = t.group(1)
                    hook_code = ""
                    count = 0
            else:
                p = re.compile('Function: ([\w_\d]+\.(dll|DLL))!([\w_\d]+)')
                t = p.match(line)
                if t:
                    module = t.group(1)
                    export = t.group(3)
                    hook_code = ""
                    count = 0
                    # print line
                    # print "%s->%s" % (module,export)
        else:
            # Function: kernel32.dll!CreateProcessA at 0x7c80236b
            p = re.compile('Function: (.+)!(.+) at 0x[a-f0-9]{8}')
            t = p.match(line)
            if t:
                module = t.group(1)
                export = t.group(2)
                hook_code = ""
                count = 0
                # print "kmd: %s" % (export)

        # Check for whitelist

        p = re.compile('Hooking module: (.+)')
        t = p.match(line)
        if t:
            hooking_module = t.group(1)
            if any(hooking_module in s for s in whitelist):
                # print "%s is whitelisted" % hooking_module
                whitelisted_patch = True
            else:
                # print "%s is NOT whitelisted" % hooking_module
                whitelisted_patch = False

                # Check if we reached disassembly of the patch:
        p = re.compile('Disassembly\(0\):')
        t = p.match(line)
        if t:
            in_patch_disassembly = True
            # print "Now in dissassembly!"

        #
        if (in_patch_disassembly):
            # print line
            p = re.compile('Disassembly\(1\):')
            t = p.match(line)
            if t:
                disasm_code_started = True
                # print "disasm started"
            elif (disasm_code_started):
                # print "Hookmodule: %s In patch disassebly: %s!%s - %s" % (hooking_module,module,export,line)
                # print "D: " + line

                arr = line.split()
                if ((not line.isspace()) & (not line.startswith("*")) & (count < 12)):
                    try:
                        hook_code += arr[1]
                        count = count + 1
                    except:
                        print
                        '[*] Skipping corruped hook line'

        # If this is the end of the hook, process it:
        p = re.compile('^[\*]{72}')
        t = p.match(line)
        if t:
            disasm_code_started = False
            in_patch_disassembly = False

            entry = {}

            if (process != ''):
                entry['process_name'] = process
            else:
                entry['process_name'] = 'unknown'

            entry['module'] = module
            entry['export'] = export
            entry['hook_code'] = hook_code
            entry['hook disassembly'] = ''
            entry['hooking_module'] = hooking_module

            offset = 0
            outDis = []

            hex_data = hook_code.decode("hex")

            while offset < len(hex_data):
                i = pydasm.get_instruction(hex_data[offset:], pydasm.MODE_32)
                tmp = pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, offset)
                outDis.append(tmp)
                if not i:
                    return outDis
                offset += i.length
            entry['hook disassembly'] = outDis

            if (hooking_module == '<unknown>'):
                hooks_count = hooks_count + 1
                hook_data.append(entry)

            hooking_module = ''
            hook_code = ''
            module = ''
            export = ''

    original_apihooks.close()

    if hooks_count > 0:
        hooks_json = json.dumps(hook_data, indent=4, sort_keys=True)
        with open (os.path.join(get_workdir_path(malware_sample),'code.hooks'), 'w+') as hooks:
            hooks.write(hooks_json)

        db_connection = DataBaseConnection()

        # Adding tag to sample:
        db_connection.add_tag("Hooks_APIs", malware_sample)
