from pywerview.functions.net import NetRequester
import argparse
import sys

BANNER = """  _  ___              ____          _   _      
 | |/ (_)_ __   __ _ / ___|__ _ ___| |_| | ___ 
 | ' /| | '_ \\ / _` | |   / _` / __| __| |/ _ \\
 | . \\| | | | | (_| | |__| (_| \\__ \\ |_| |  __/
 |_|\\_\\_|_| |_|\\__, |\\____\\__,_|___/\\__|_|\\___|
               |___/ I'm a king without a land.
"""

LAPSv2_QUERIED_ATTRIBUTES = ['mslaps-passwordexpirationtime']
LAPSv1_QUERIED_ATTRIBUTES = ['ms-mcs-admpwdexpirationtime']
CREATORSID_QUERIED_ATTRIBUTES = ['ms-ds-creatorsid', 'dnshostname', 'samaccountname']
LDAP_FILTER_NOT_ACCOUNTDISABLE = '(!(UserAccountControl:1.2.840.113556.1.4.803:=2))'
LDAP_FILTER_MDT = '(objectclass=intellimirrorSCP)'
LDAP_FILTER_NOT_DC = '(!(primarygroupid=516))'
LDAP_FILTER_DN = '(distinguishedname={})'

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def argparser(argv):
    # Parsing des arguments
    arg_parser = argparse.ArgumentParser(prog='kingcastle.py', description='\n Quick overview of the Windows domain.')
    arg_parser.add_argument('-u', '--user', required=True, help='Username used to connect to the Domain Controller')
    arg_parser.add_argument('-w', '--workgroup', required=True, dest='domain', help='Name of the domain we authenticate with')
    arg_parser.add_argument('-p', '--password', help='Password associated to the username')
    arg_parser.add_argument('--hashes', action='store', metavar = 'LMHASH:NTHASH', help='NTLM hashes, format is [LMHASH:]NTHASH')
    arg_parser.add_argument('-t', '--dc-ip', dest='domain_controller', help='IP address of the Domain Controller to target')
    arg_parser.add_argument('--debug', action="store_true", help='Debug mode')
    args = arg_parser.parse_args(argv)

    # Dealing with hashes
    if args.hashes:
        try:
            args.lmhash, args.nthash = args.hashes.split(':')
        except ValueError:
            args.lmhash, args.nthash = 'aad3b435b51404eeaad3b435b51404ee', args.hashes
        finally:
            args.password = str()
    else:
        args.lmhash = args.nthash = str()

    if args.password is None and not args.hashes:
        from getpass import getpass
        args.password = getpass('Password:')
    return args

def okgreen(text):
    return bcolors.OKGREEN + text + bcolors.ENDC
    
def fail(text):
    return bcolors.FAIL + text + bcolors.ENDC

print(BANNER)

args = argparser(sys.argv[1:])

# Configuration
lmhash = args.lmhash
nthash = args.nthash
domain_controller = args.domain_controller
domain = args.domain
user = args.user
password = args.password

debugprint = print if args.debug else lambda *a, **k: None

# Let's go!
print("[+] Let's go!")
debugprint("[-] Creating NetRequester")
netrequester = NetRequester(domain_controller, domain, user, password, lmhash, nthash)

print("[+] ADCS?")
results = netrequester.get_netpki()
if results:
    print(okgreen('ADCS installed!'))
    for result in results:
        print('    - {0} on {1}'.format(result.name, result.dnshostname))
        print('    - certipy find -u {0}@{1} -p {2} -enabled'.format(user, domain, password))
else:
    print(fail('Not found'))

print("[+] MDT?")
results = netrequester.get_adobject(custom_filter=LDAP_FILTER_MDT, attributes=['cn','netbootserver'])
if results:
    print(okgreen('MDT installed!'))
    for result in results:
        debugprint("[-] Calling get_netcomputer to retrieve the dnshostname")
        try:
            dnshostname = netrequester.get_netcomputer(custom_filter=LDAP_FILTER_DN.format(result.netbootserver), attributes=['dnshostname'])[0]
            dnshostname =dnshostname.dnshostame
        except IndexError:
            debugprint("[-] dnshostname not found")
            dnshostname = 'UKNOWN'
        print('    - {0} on {1}'.format(result.cn, dnshostname))
        print('    - check rights on \\\\{0}\\DeploymentShare$ !'.format(dnshostname))
else:
    print(fail('Not found'))

print("[+] Computers with unconstrained delegation?")
results = netrequester.get_netcomputer(unconstrained=True, custom_filter=LDAP_FILTER_NOT_DC)
if results:
    print(okgreen('ok'))
    for result in results:
        print('    - {0}'.format(result.samaccountname))
else:
    print(fail('Not found'))

print("[+] Users with unconstrained delegation?")
results = netrequester.get_netuser(unconstrained=True, custom_filter=LDAP_FILTER_NOT_ACCOUNTDISABLE)
if results:
    print(okgreen('ok'))
    for result in results:
        print('    - {0}'.format(result.samaccountname))
else:
    print(fail('Not found'))

print("[+] Trust?")
results = netrequester.get_netdomaintrust(queried_domain=domain)
if results:
    print(okgreen('Trust found!'))
    for result in results:
        print('    - {0} with {1} ({2})'.format(result.trustdirection, result.trustpartner, ', '.join(result.trustattributes)))
else:
    print(fail('Not found'))

print("[+] Users with SPN?")
results = netrequester.get_netuser(spn=True, custom_filter=LDAP_FILTER_NOT_ACCOUNTDISABLE)
if results:
    print(okgreen('ok'))
    for result in results:
        print('    - {0}'.format(result.samaccountname))
else:
    print(fail('Not found'))

print("[+] Users without pre-authentication?")
results = netrequester.get_netuser(preauth_notreq=True, custom_filter=LDAP_FILTER_NOT_ACCOUNTDISABLE)
if results:
    print(okgreen('ok'))
    for result in results:
        print('    - {0}'.format(result.samaccountname))
else:
    print(fail('Not found'))

print("[+] Pre-created targets")
results = netrequester.get_netcomputer(pre_created=True)
if results:
    print(okgreen('ok'))
    for result in results:
        print('    - {0}'.format(result.samaccountname))
else:
    print(fail('Not found'))

print("[+] Is LAPS installed?")
try:
    results = netrequester.get_netcomputer(attributes=LAPSv1_QUERIED_ATTRIBUTES)
    print(fail('LAPSv1 is installed, but check on all computers'))
except:
    print(okgreen('LAPSv1 is not installed'))

try:
    results = netrequester.get_netcomputer(attributes=LAPSv2_QUERIED_ATTRIBUTES)
    print(fail('LAPSv2 is installed but check on all computer'))
except:
    print(okgreen('LAPSv2 is not installed'))

print("[+] ms-DS-CreatorSID?")
creatorsid = False
results = netrequester.get_netcomputer(attributes=CREATORSID_QUERIED_ATTRIBUTES)
for result in results:
    if getattr(result,'ms-ds-creatorsid'):
        creatorsid = True
        try:
            samaccountname_owner = netrequester.get_adobject(queried_sid=getattr(result,'ms-ds-creatorsid'), attributes=['samaccountname'])[0]
            samaccountname_owner = samaccountname_owner.samaccountname
        except IndexError:
            debugprint("[-] Cannot translate {}".format(getattr(result,'ms-ds-creatorsid')))
            samaccountname_owner = 'UNKNOWN'
        print('    - {0} created {1}'.format(samaccountname_owner, result.samaccountname))

if not creatorsid:
   print(fail('Not found'))
print("[+] The End!")

