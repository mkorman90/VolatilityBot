import json
import logging
import os
import re
import pefile

from pefile import PEFormatError

from volatilitybot.conf.static_config import DLLS_IN_SYSDIR
from volatilitybot.lib.core.memory_utils import execute_volatility_command, dump_process, dump_dll
from volatilitybot.lib.core.sample import SampleDump
from volatilitybot.conf.config import EXPLOITABLE_PROCESS_NAMES
from volatilitybot.lib.common.utils import create_workdir
from volatilitybot.lib.common.pe_utils import fix_pe_from_memory, static_analysis, get_strings
from volatilitybot.lib.common.pslist import get_new_pslist


# TODO: Heuristic for drivers of uncommon path or size
#       ldrmodules anomalies
#

def run_heuristics(memory_instance, workdir=None, dump_objects=False):
    """
    Execute all required heuristics
    :param memory_instance: an instance of memory object
    :param workdir: path to the workdir
    :param dump_objects: wether to dump suspicious results or not
    :return: dictionary containing all heuristics results
    """
    pslist = get_new_pslist(memory_instance)

    suspicious_drivers_by_ssdt = heuristic_ssdt(memory_instance, pslist=pslist, workdir=workdir,dump_objects=dump_objects)

    suspicious_procs_by_dst_port = heuristic_dest_port_anomallies(memory_instance, pslist=pslist, workdir=workdir,
                                                                  dump_objects=dump_objects)

    suspicious_loaded_dlls_by_count = heuristic_dll_uncommon_on_machine(memory_instance, pslist=pslist, workdir=workdir,
                                                                        dump_objects=dump_objects)

    suspicious_processes_by_sids = heuristic_by_process_sids(memory_instance, pslist=pslist, workdir=workdir,
                                                             dump_objects=dump_objects)

    injected_code = heuristic_injected_code(memory_instance, pslist=pslist, workdir=workdir, dump_objects=dump_objects)

    suspect_processes = heuristic_exploitable_parent(memory_instance, workdir=workdir, dump_objects=dump_objects)

    suspicious_dlls = heuristic_libraries_by_path(memory_instance, pslist=pslist, workdir=workdir,
                                                  dump_objects=dump_objects)

    suspicious_procs_by_privs = heuristics_process_privileges(memory_instance, pslist=pslist, workdir=workdir,
                                                              dump_objects=dump_objects)

    suspicious_handles = heuristic_suspicious_handles(memory_instance, pslist=pslist, workdir=workdir,
                                                      dump_objects=dump_objects)

    result = {'pslist': pslist, 'injected_code': injected_code, 'suspicious_processes_by_handles': suspect_processes,
              'suspicious_handles': suspicious_handles, 'suspicious_dlls': suspicious_dlls,
              'suspect_processes_by_priv': suspicious_procs_by_privs,
              'suspicious_procs_by_dst_port': suspicious_procs_by_dst_port,
              'suspicious_loaded_dlls_by_count': suspicious_loaded_dlls_by_count,
              'suspicious_processes_by_sids': suspicious_processes_by_sids,
              'suspicious_drivers_by_ssdt': suspicious_drivers_by_ssdt}

    return result


def heuristic_exploitable_parent(memory_instance, pslist=None, workdir=None, dump_objects=False):
    """
    Dump executable processes according to parent process name
    :param memory_instance: an instance of memory object
    :param pslist: list of processes obtained from get_new_pslist
    :param workdir: path to the workdir
    :param dump_objects: wether to dump suspicious results or not
    :return:
    """
    # Get process list
    if pslist is None:
        pslist = get_new_pslist(memory_instance)

    suspect_processes = []

    for process in pslist:
        if process['Name'].lower() in EXPLOITABLE_PROCESS_NAMES:
            logging.info('Checking child of exploitable process {}'.format(process['Name']))
            for child_process in pslist:
                if child_process['PPID'] == process['PID']:
                    if child_process['Name'] != process['Name']:
                        logging.info('Found potentially exploit payload: {}'.format(child_process))
                        suspect_processes.append(child_process)

                        if dump_objects:
                            logging.info('Dumping {} due to suspicious exploitable parent'.format(child_process))
                            dump_process(memory_instance, child_process['PID'], workdir,
                                         process_name=child_process['Name'],
                                         memdump=True)

    return suspect_processes


def heuristic_by_process_sids(memory_instance, pslist=None, workdir=None, dump_objects=False):
    """
    Dump suspicious processes, according to running user
    :param memory_instance: an instance of memory object
    :param pslist: list of processes obtained from get_new_pslist
    :param workdir: path to the workdir
    :param dump_objects: wether to dump suspicious results or not
    :return: dictionary of suspect code injection sections inside processes
    """

    process_whitelist = ['System', 'msiexec.exe', 'VMwareService.e', 'spoolsv.exe', 'svchost.exe', 'vmacthlp.exe',
                         'services.exe', 'winlogon.exe', 'csrss.exe', 'smss.exe', 'lsass.exe','vmtoolsd.exe']

    suspicious_processes = list()

    # Get process list
    if pslist is None:
        pslist = get_new_pslist(memory_instance)

    if workdir is None:
        workdir = create_workdir()

    # "columns": ["PID", "Process", "SID", "Name"]}
    output = execute_volatility_command(memory_instance, 'getsids')
    for priv in output:
        if priv['SID'] == 'S-1-5-18' and priv['Process'] not in process_whitelist:
            logging.info('Suspicious priv: {}'.format(priv))
            suspicious_processes.append(priv)
            if dump_objects:
                logging.info('Dumping {} due to suspicious SID'.format(priv['PID']))
                dump_process(memory_instance, priv['PID'], workdir,
                             process_name=priv['Process'],
                             memdump=True)
    return suspicious_processes


def heuristic_injected_code(memory_instance, pslist=None, workdir=None, dump_objects=False, delete_non_pe=False):
    """
    Dump injected code
    :param memory_instance: an instance of memory object
    :param pslist: list of processes obtained from get_new_pslist
    :param workdir: path to the workdir
    :param dump_objects: wether to dump suspicious results or not
    :param delete_non_pe: delete non PE files or not, they could be shellcode injections
    :return: dictionary of suspect code injection sections inside processes
    """
    # Get process list
    if pslist is None:
        pslist = get_new_pslist(memory_instance)

    if workdir is None:
        workdir = create_workdir()

    injected_dumps_list = list()
    if dump_objects:
        logging.info('Going to dump injected processes to {}'.format(workdir))
        output = execute_volatility_command(memory_instance, 'malfind', extra_flags='-D {}/'.format(workdir),
                                            has_json_output=False)

        # Find malfind injections that are binaries, and rename them
        for single_dump in os.scandir(workdir):
            splitted_line = single_dump.path.strip().split('.')
            if len(splitted_line) == 4:
                offset = splitted_line[1]
                imagebase = splitted_line[2]
                try:
                    pe = pefile.PE(single_dump.path)

                    fixed_pe = fix_pe_from_memory(pe, imagebase=imagebase)
                    # Get original process name
                    procname = "unknown"

                    for process in pslist:
                        if str(process['Offset(V)']) == str(int(offset, 16)):
                            logging.info("Found process name: {}".format(process['Name']))
                            procname = process['Name']
                            pid = str(process['PID'])
                            break

                    outputpath = os.path.join(workdir, procname + '.' + offset + '.' + imagebase + '.fixed_bin')
                    logging.info('Dumping fixed PE to {}'.format(outputpath))
                    fixed_pe.write(filename=outputpath)
                    pe.close()

                    if procname != 'unknown':
                        injected_dumps_list.append({'path': outputpath, 'process_name': procname, 'pid': pid})
                    else:
                        injected_dumps_list.append(outputpath)

                    current_dump = SampleDump(outputpath)
                    with open(outputpath + '.strings.json', 'w') as strings_output_file:
                        strings_output_file.write(json.dumps(get_strings(current_dump), indent=4))

                    with open(outputpath + '.static_analysis.json', 'w') as strings_output_file:
                        strings_output_file.write(json.dumps(static_analysis(current_dump), indent=4))

                except PEFormatError:
                    logging.info('Corrupted, or not PE file...')
                    if delete_non_pe:
                        os.remove(single_dump)
                    pass

        result = {'PE_dump_list': injected_dumps_list}
    else:
        logging.info('Not output workdir defined, not going to dump injected processes.')
        output = execute_volatility_command(memory_instance, 'malfind')
        result = {'malfind_output': output}

    return result


def heuristic_libraries_by_path(memory_instance, pslist=None, workdir=None, dump_objects=False):
    """
    Heuristics by path, using statistics and dlllist
    :param memory_instance: memory instance object
    :param pslist: list of loaded processes created by get_new_pslist()
    :param workdir: path to working directory
    :param dump_objects: wether to dump suspicious object or not
    :return: dictionary of suspect processes
    """
    loaded_dlls = execute_volatility_command(memory_instance, 'dlllist')

    statistic_dict = dict()
    suspicious_dlls = list()

    max_files_threshold = 2
    statistic_anomalies_list = ['\\systemroot\\system32\\smss.exe', 'c:\\windows\\explorer.exe',
                                'c:\\program files\\internet explorer\\ieproxy.dll']

    for loaded_dll in loaded_dlls:
        # loaded_dll['Path'].lower()
        folder_path = '\\'.join(loaded_dll['Path'].lower().split('\\')[0:-1])
        try:
            statistic_dict[folder_path] += 1
        except KeyError:
            statistic_dict[folder_path] = 1

    suspect_path_list = list()
    sorted_dict = sorted(statistic_dict.items(), key=lambda x: x[1], reverse=True)
    for path in sorted_dict:
        if path[1] < max_files_threshold:
            print(path)
            suspect_path_list.append(path[0])

    for loaded_dll in loaded_dlls:
        for suspect_path in suspect_path_list:
            if '\\'.join(loaded_dll['Path'].lower().split('\\')[0:-1]) == suspect_path.lower():
                if loaded_dll['Path'].lower() not in statistic_anomalies_list:
                    suspicious_dlls.append(loaded_dll)
                    if dump_objects:
                        logging.info('Going to dump {} due to suspicious path'.format(loaded_dll))
                        dump_dll(memory_instance, loaded_dll['Pid'], loaded_dll['Base'], workdir)

    return suspicious_dlls


def heuristic_suspicious_handles(memory_instance, pslist=None, workdir=None, dump_objects=False):
    """
    Heuristics by suspicious handles
    :param memory_instance: memory instance object
    :param pslist: list of loaded processes created by get_new_pslist()
    :param workdir: path to working directory
    :param dump_objects: wether to dump suspicious object or not
    :return: dictionary of suspect processes
    """
    handles_list = execute_volatility_command(memory_instance, 'handles', extra_flags='-s')
    supported_handles = ['Key', 'File', 'Mutant', 'Thread']

    # Initiate a dict with scoring per PID...
    process_scoring = dict()
    for process in pslist:
        process_scoring[process['PID']] = {'Name': process['Name'], 'PID': process['PID'], 'PPID': process['PPID'],
                                           'susp_keys': 0,
                                           'susp_files': 0,
                                           'susp_mutex': 0,
                                           'susp_thread_handles': 0,
                                           'Key': list(), 'File': list(), 'Mutant': list(),
                                           'Thread': list()}

    # for each process, add its handles to his dict
    for handle in handles_list:
        if handle['Type'] in supported_handles:
            try:
                process_scoring[handle['Pid']][handle['Type']].append(handle)
            except KeyError:
                logging.info('PID does not exists ({})'.format(handle['Pid']))

    # Get a dictionary of running processes by name, for easier iteration (from pslist)
    running_processes = dict()
    for running_process in pslist:
        running_processes[str(running_process['PID'])] = running_process['Name']

    # Anomaly detection phase:

    # Find processes with handles to threads in other processes...
    for process_pid in process_scoring:
        for thread_handle in process_scoring[process_pid]['Thread']:
            # Get pid from regex:
            m = re.search(r'^TID (\d{2,4})\sPID\s(\d{2,4})$', thread_handle['Details'])
            if m:
                tid = m.group(1)
                pid = m.group(2)
                if pid != str(process_pid) and pid != str(process_scoring[process_pid]['PPID']) and \
                                process_scoring[process_pid]['Name'] != 'csrss.exe':

                    try:
                        if process_scoring[process_pid]['Name'] == 'services.exe' and running_processes[
                            pid] == 'lsass.exe':
                            continue
                        if process_scoring[process_pid]['Name'] == 'lsass.exe' and running_processes[
                            pid] == 'svchost.exe':
                            continue

                        logging.info(
                            'This process has an handle to a thread in another process: {}-{} ---> {} ({})'.format(
                                process_scoring[process_pid]['Name'], process_pid, thread_handle['Details'],
                                running_processes[pid]))
                    except KeyError:
                        logging.info('This process has an handle to a thread in another process: {}-{} ---> {}'.format(
                            process_scoring[process_pid]['Name'], process_pid, thread_handle['Details']))

                    process_scoring[process_pid]['susp_thread_handles'] += 1

    # Mutants (i.e statistically outstanding mutants)
    # TODO: import fuzzywuzzy, from fuzzywuzzy import fuzz, fuzz.ratio(a,b)

    # Files (i.e executables/DLLs from unusual paths)

    # Keys (i.e persistency keys...)

    # Create a final list of processes with more suspicious handles than the treshold:
    threshold = 0
    suspect_processes = list()
    for process_pid in process_scoring:
        if (process_scoring[process_pid]['susp_keys'] + process_scoring[process_pid]['susp_files'] +
                process_scoring[process_pid]['susp_mutex'] + process_scoring[process_pid][
            'susp_thread_handles']) > threshold:
            suspect_processes.append({'pid': process_pid, 'name': process_scoring[process_pid]['Name'],
                                      'susp_keys': process_scoring[process_pid]['susp_keys'],
                                      'susp_files': process_scoring[process_pid]['susp_files'],
                                      'susp_mutex': process_scoring[process_pid]['susp_mutex'],
                                      'susp_thread_handles': process_scoring[process_pid]['susp_thread_handles']})

    return suspect_processes


def heuristics_process_privileges(memory_instance, pslist=None, workdir=None, dump_objects=False):
    """
    Find suspicious processes according to process privileges
    :param memory_instance: memory instance object
    :param pslist: list of loaded processes created by get_new_pslist()
    :param workdir: path to working directory
    :param dump_objects: wether to dump suspicious object or not
    :return: dictionary of suspect processes
    """
    suspicious_privileges = ['SeDebugPrivilege', 'SeTcbPrivilege',
                             'SeTrustedCredManAccessPrivilege']

    privs_list = execute_volatility_command(memory_instance, 'privs')

    procs_with_suspicious_privs = list()
    dumped_process_list = list()
    for privilege in privs_list:
        if privilege['Privilege'] in suspicious_privileges:
            attributes_list = privilege['Attributes'].split(',')
            if 'Present' in attributes_list and 'Enabled' in attributes_list and 'Default' not in attributes_list:
                print(json.dumps(privilege))
                procs_with_suspicious_privs.append(privilege)

                if dump_objects and privilege['Pid'] not in dumped_process_list:
                    logging.info('Dumping {} due to suspicious privileges'.format(privilege['Pid']))
                    dump_process(memory_instance, privilege['Pid'], workdir, process_name=privilege['Process'])
                    dumped_process_list.append(privilege['Pid'])

    return procs_with_suspicious_privs


def heuristic_dest_port_anomallies(memory_instance, pslist=None, workdir=None, dump_objects=False):
    whitelisted_dest_ports = ['80', '443', '8443', '53', '3889']

    suspicious_processes = list()
    connections = execute_volatility_command(memory_instance, 'connections')
    for conn in connections:
        dst_ip, dst_port = conn['RemoteAddress'].split(':')
        if dst_port not in whitelisted_dest_ports:
            suspicious_processes.append(conn)
            if dump_objects:
                procname = 'unknown'
                for process in pslist:
                    if str(process['Offset(V)']) == str(conn['Offset(V)']):
                        logging.info("Found process name: {}".format(process['Name']))
                        procname = process['Name']
                        pid = str(process['PID'])
                        break
                dump_process(memory_instance, conn['PID'], workdir, process_name=procname)

    return suspicious_processes


def heuristic_dest_ip_malicious_in_vt(memory_instance, pslist=None, workdir=None, dump_objects=False):
    pass


def heuristic_dll_uncommon_on_machine(memory_instance, pslist=None, workdir=None, dump_objects=False):
    loaded_dlls = execute_volatility_command(memory_instance, 'dlllist')

    suspect_path_list = list()
    loaded_dlls_counter = dict()
    for loaded_dll in loaded_dlls:
        try:
            loaded_dlls_counter[loaded_dll['Path']]['counter'] += 1
        except KeyError:
            loaded_dlls_counter[loaded_dll['Path']] = {'counter': 0, 'first_seen': loaded_dll}

    for key in loaded_dlls_counter:
        if loaded_dlls_counter[key]['first_seen']['Path'] not in DLLS_IN_SYSDIR:
            if loaded_dlls_counter[key]['counter'] == 1 and loaded_dlls_counter[key]['first_seen']['LoadCount'] == 1:
                print('Going to dump: {}'.format(loaded_dlls_counter[key]['first_seen']))

                if dump_objects:
                    dump_dll(memory_instance, loaded_dlls_counter[key]['first_seen']['Pid'],
                             loaded_dlls_counter[key]['first_seen']['Base'], workdir)
                suspect_path_list.append(loaded_dlls_counter[key]['first_seen'])

    return suspect_path_list


def heuristic_ssdt(memory_instance, pslist=None, workdir=None, dump_objects=False):
    ssdt = execute_volatility_command(memory_instance, 'ssdt')

    legitimate_owners = ['ntoskrnl.exe', 'win32k.sys']

    known_owners = list()
    for entry in ssdt:
        if entry['Owner'] not in legitimate_owners and entry['Owner'] not in known_owners:
            print('New ownwer: {}'.format(entry))
            known_owners.append(entry['Owner'])

    for driver_name in known_owners:
        # /usr/local/bin/vol.py --profile WinXPSP2x86 -f "/home/MemoryDumps/APT.img" moddump -r irykmmww.sys -D /tmp
        execute_volatility_command(memory_instance,'moddump',extra_flags='-r {} -D {}'.format(driver_name,workdir))

    return known_owners
