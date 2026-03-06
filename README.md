# KingCastle

I was bored to type the same commands each time I started a new internal pentest. So here comes KingCastle. It displays a quick overview of the domain based on LDAP queries. This script **does not perform** any attacks, consider it as a cheat sheet, to quickly see low hanging fruits. Obviously not OPSEC safe.

Extracted info:
  * [ADCS](https://www.thehacker.recipes/ad/movement/adcs/)
  * [MDT](https://trustedsec.com/blog/red-team-gold-extracting-credentials-from-mdt-shares)
  * [unconstrained delegations](https://en.hackndo.com/constrained-unconstrained-delegation/)
  * [Domain Trusts](https://www.thehacker.recipes/ad/movement/trusts/)
  * [Kerberoasting](https://www.thehacker.recipes/ad/movement/kerberos/kerberoast)
  * [ASREProasting](https://www.thehacker.recipes/ad/movement/kerberos/asreproast)
  * [LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
  * [ms-DS-CreatorSID](https://blog.nviso.eu/2023/10/26/most-common-active-directory-misconfigurations-and-default-settings-that-put-your-organization-at-risk/)

Tested in prod, but use at your own risk.

## Usage

```
  _  ___              ____          _   _      
 | |/ (_)_ __   __ _ / ___|__ _ ___| |_| | ___ 
 | ' /| | '_ \ / _` | |   / _` / __| __| |/ _ \
 | . \| | | | | (_| | |__| (_| \__ \ |_| |  __/
 |_|\_\_|_| |_|\__, |\____\__,_|___/\__|_|\___|
               |___/ I'm a king without a land.

usage: kingcastle.py [-h] -u USER -w DOMAIN [-p PASSWORD] [--hashes LMHASH:NTHASH] [-t DOMAIN_CONTROLLER] [--debug]

Quick overview of the Windows domain.

options:
  -h, --help            show this help message and exit
  -u USER, --user USER  Username used to connect to the Domain Controller
  -w DOMAIN, --workgroup DOMAIN
                        Name of the domain we authenticate with
  -p PASSWORD, --password PASSWORD
                        Password associated to the username
  --hashes LMHASH:NTHASH
                        NTLM hashes, format is [LMHASH:]NTHASH
  -t DOMAIN_CONTROLLER, --dc-ip DOMAIN_CONTROLLER
                        IP address of the Domain Controller to target
  --debug               Debug mode
```

## Example

```
$ python kingcastle.py -u daenerys.targaryen -w essos.local -t 192.168.56.24 -p 'BurnThemAll!'
  _  ___              ____          _   _      
 | |/ (_)_ __   __ _ / ___|__ _ ___| |_| | ___ 
 | ' /| | '_ \ / _` | |   / _` / __| __| |/ _ \
 | . \| | | | | (_| | |__| (_| \__ \ |_| |  __/
 |_|\_\_|_| |_|\__, |\____\__,_|___/\__|_|\___|
               |___/ I'm a king without a land.

[+] Let's go!
[+] ADCS?
ADCS installed!
    - ESSOS-CA on braavos.essos.local
    - certipy find -u daenerys.targaryen@essos.local -p BurnThemAll! -enabled
[+] MDT?
Not found
[+] Computers with unconstrained delegation?
Not found
[+] Users with unconstrained delegation?
Not found
[+] Trust?
Trust found!
    - bidirectional with sevenkingdoms.local (TRUST_ATTRIBUTE_FOREST_TRANSITIVE)
[+] Users with SPN?
ok
    - sql_svc
[+] Users without pre-authentication?
ok
    - missandei
[+] Pre-created targets
Not found
[+] Is LAPS installed?
LAPSv1 is installed, but check on all computers
LAPSv2 is not installed
[+] ms-DS-CreatorSID?
Not found
[+] The End!
```
