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
        print('[+] Found vulnerable host! {}:{} - {}'.format(ip, port, msf_mod))

        return exploit_data


def main():
    report = parse_nessus()
    nes_exploits = get_nes_exploits(report)
    print('')
    print('[+] Nessus exploit data:')
    for x in nes_exploits:
        print(x)
    print('')
    print('[*] Try running "dir(report)" in the embedded shell to see the methods of the parsed Nessus report object')
    print('[*] Example method execution: report.hosts\n')
    embed()

if __name__ == '__main__':
    args = parse_args() # This makes the 'args' variable global
    check_for_args()
    main()
