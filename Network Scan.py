import re
import subprocess

#LINUX ONLY FOR THE TIME BEING

class NetObj:
    def __init__(self, ip="169.254.254.254",subnet="24",broadcast="unspecified", mac="unspecified", label="unspecified interface", display='single'):
        self.ip = ip
        self.mac = mac
        self.label = label
        self.broadcast = broadcast
        self.cidr_mask = subnet
        self.display_mode = display
        self.ports = []
        if ip != "169.254.254.254":
            self.subnet = f'{ip}/{subnet}'
        else:
            self.subnet = 'unspecified'
    def __str__(self) -> str: #I want to use list/tuple comprehension to expand these out in the future--that way we can ignore extraneous or unspecified values
        if self.display_mode == 'single':
            return f'Interface: {self.label}\nMAC Addr: {self.mac}\nIP Addr: {self.ip}\nSubnet CIDR Notation: {self.subnet}\nBroadcast Addr: {self.broadcast}\n'
    def __repr__(self) -> str:
        return f'Interface: {self.label}\nMAC Addr: {self.mac}\nIP Addr: {self.ip}\nSubnet CIDR Notation: {self.subnet}\nBroadcast Addr: {self.broadcast}\n'
    def table(self):
        return f'|{self.label}|{self.mac}|{self.ip}|{self.subnet}|{self.broadcast}|'
    def AddPorts(self, ports_list):
        if type(ports_list) == str or type(ports_list) == int:
            self.ports.append(ports_list)
        elif type(ports_list) == list:
            for item in ports_list:
                self.ports.append(item)

def SendCommand(command, args='XXXXX'):
    if args != 'XXXXX': #I know I know, this is a crap way to make this optional
        gather_ouput = subprocess.Popen([command, args],stdout=subprocess.PIPE)
    else:
        gather_ouput = subprocess.Popen([command],stdout=subprocess.PIPE)
    unparsed = str(gather_ouput.communicate()) #only doing this parsing because I'm not sure what the purpose of the tuple is, and I just want to remove it for now
    parsed = unparsed.replace("(b'","").replace("\\n', None)","")
    return parsed

print('Running...\nFinding IP Address: ')

interface_output = SendCommand('ip','addr') #next step--parse this to relate the data back to the list of IP addresses. Maybe I could even parse this first, turning it into NetObj classes

onboard_interfaces = []
interface_raw = re.split("^\d+:|\\\\n\d+:",interface_output)
interface_raw.remove('')
for intf in interface_raw: #this is the first implementation of a NetObj class; not how I originally envisioned it but it helps move things along for finding own IP addresses
    interface_label = re.search('^.+: <',intf)
    interface_label = interface_label.group(0).replace(": <","")
    mac = re.search('..:..:..:..:..:..',intf)
    mac = mac.group(0)
    ip_addresses = re.findall('\d+\.\d+\.\d+\.\d+',intf)
    subnet_cidr = re.search('\d+\.\d+\.\d+\.\d+/\d+',intf)
    if len(ip_addresses) > 0: #if we can't find IP addresses, we assume there are none associated with that port. So, not including it in the class instance
        broadcast_addr = ip_addresses[1]
        subnet_cidr = subnet_cidr.group(0)
        subnet_cidr = subnet_cidr.split('/')
        subnet_cidr = subnet_cidr[1] #this should get the subnet as CIDR numbers only; it's under 'try' in case we can't find an ip address for that port (we don't want it to error out when it can't find the subnet)
        #print(f'Interface: {interface_label}\nMAC Addr: {mac}\nIP Addr: {ip_addresses[0]}\nSubnet CIDR Notation: {ip_addresses[0]}/{subnet_cidr}\nBroadcast Addr: {broadcast_addr}\n')
        interface_info = NetObj(label=interface_label,mac=mac, ip=ip_addresses[0],subnet=subnet_cidr, broadcast=broadcast_addr)
    else:
        #print(f'Interface: {interface_label}\nMAC Addr: {mac}\n')
        interface_info = NetObj(label=interface_label,mac=mac)
    onboard_interfaces.append(interface_info)

#subprocess.Popen('clear')

#above, we collected data from our own interfaces and put them in instances of the NetObj class
#now, we'll begin running NMAP scans, given an IP address range and some instructions
#eventually, here, there will be a selection menu for choosing or typing what address range we want, from the interfaces above

print("Looks like there are a few different subnets that could be scanned, based on your interfaces. Select from the menu below:")
onboard_selection = {}
i = 1
for net_object in onboard_interfaces:
    if net_object.subnet != 'unspecified' and net_object.label != ' lo':
        onboard_selection[str(i)] = net_object
        print(f'{i}: {net_object.label} - {net_object.subnet}')
        i += 1

select = input('Enter number>>> ')
scanning_interface = onboard_selection[select]
#print(scanning_interface)

#.\nmap -A -F 192.168.2.211/20
#ping-only scan: nmap -sn IPADDR
#"reasonably fast": nmap -T4 -F IPADDR
#"quicker": nmap -T4 -F -A IPADDR
#"Intense scan, without ping" (in case hosts ignore ping requests): nmap -T4 -F -A -Pn

netscan_output = subprocess.Popen(['nmap',scanning_interface.subnet],stdout=subprocess.PIPE)
netscan_output = str(netscan_output.communicate())
netscan_output = netscan_output.replace("(b'","").replace("\\n', None)","")

