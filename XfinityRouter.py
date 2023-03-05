import requests
import re
import csv
from bs4 import BeautifulSoup

"""
XfinityRouter Project
---------------------
This project was designed to control my home's Xfinity router using the HTTP
interface for the device. It currently can:
    - Login to the device
    - Retrieve the list of devices currently connected to the network
    - Add a port forwarding entry (open a port programmatically)
    - Enable/Disable port forwarding

Potential Uses
    - Build a history of connected devices. Pattern-finding algorithms can use this
      information to predict when a specific device will be on the network.
    - To extend the functionality of my HomeServer project. I can open network ports
      for a brief period of time so that I am more protected from outside attacks.
"""

pattern_name = re.compile(r'')
pattern_ipv4 = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
pattern_mac = re.compile(r'(?:[0-9a-fA-F]:?){12}')

def getIdentifiers(buffer: str):
    segments = buffer.split()
    ids = {}
    ids['name'] = buffer.split()[0]
    ipv4 = re.findall(pattern_ipv4, buffer)
    mac = re.findall(pattern_mac, buffer)
    if(ipv4):
        ids['ipv4'] = ipv4[0]
    if(mac):
        ids['mac'] = mac[0]
    return ids

def grabChunk(buffer: str):
    """Returns None or a chunk of text in `buffer` after `startStr` and before `endStr`."""
    if buffer.find(startStr) == -1:
        return None
    if buffer.find(endStr) == -1:
        return None

    startIndex = buffer.find(startStr) + len(startStr)
    endIndex = buffer[startIndex:].find(endStr) + startIndex
    return buffer[startIndex:endIndex]  # Should be text sandwiched between the 2 argument strings


class Router:
    """A class that interacts with an Xfinity router."""

    # Constant web paths
    # addForwardForm = "/goform/port_forwarding_add"
    # addForwardPage = "/port_forwarding_add.asp"
    # portForwardingForm = "/goform/port_forwarding"
    # portForwardingPath = "/port_forwarding.asp"
    loginForm = "/check.jst"
    connectedDevicesPage = "/connected_devices_computers.jst"
    atAGlancePage = "/at_a_glance.jst"
    add_managed_site_form = "/actionHandler/ajaxSet_add_blockedSite.jst"
    managed_sites_page = "/managed_sites.jst"
    set_restricted_device_form = "/actionHandler/ajaxSet_trust_computer.jst"

    block_work_hours = {
        "alwaysBlock": "false", 
        "StartTime": "06:00", 
        "EndTime": "17:00", 
        "blockedDays": "Mon,Tue,Wed,Thu,Fri"
    }

    def __init__(self, ip="10.0.0.1", pwd_file="./password.txt", port=80):
        """Setup information for interacting with router through HTTP."""
        self.ip = ip
        self.pwd = open(pwd_file).read()
        self.port = port
        self.session = requests.Session()

    def login(self) -> bool:
        """Login to the router."""

        # Send the POST data
        self.session.get("http://%s/" % self.ip)  # Get cookies
        load = {"username": "admin",
                "password": self.pwd}
        path = "http://%s%s" % (self.ip, self.loginForm)
        print('Posting to %s...\nHeaders: %s' % (path, self.session.headers))
        response = self.session.post(path, data=load)

        # Test to see if our response is a good one or a bad one
        landingPageURL = "http://%s%s" % (self.ip, self.atAGlancePage)
        if response.url == landingPageURL:
            print('Log in success!')
            return True
        else:
            print('Log in failed! Status code: %d' % response.status_code)
            return False

    def setManagedSites(self, sites_list):
        print("Setting managed sites...")
        self.managed_sites_state = self.get_managed_sites()
        open('add_managed_site.log', 'w').close()
        with open(sites_list, 'r') as csvfile:
            datareader = csv.reader(csvfile)
            next(datareader)
            for row in datareader:
                r.addManagedSite(row)

    def addManagedSite(self, site):
        if(self.managed_sites_state.count(site[0]) > 0):
            return True

        BlockInfo = {}
        BlockInfo['URL'] = 'http://' + site[0]
        if(site[1] == 'x'):
            BlockInfo.update(self.block_work_hours)
        else:
            BlockInfo['alwaysBlock'] = 'true'
        
        load = {
            'BlockInfo': str(BlockInfo).replace('\'','\"')
        }        

        path = "http://%s%s" % (self.ip, self.add_managed_site_form)
        response = self.session.post(path, data=load)

        if '{"status":"Success!"}' in response.text:
            print('Added managed site: ' + BlockInfo['URL'])
            self.managed_sites_state.append(site[0])
            return True
        else:
            print('Add managed site %s: Status code: %d' % (BlockInfo['URL'], response.status_code))
            open('add_managed_site.log', 'a').write(response.text)
            print(load)
            return False
    
    def setRestrictedDevices(self, restricted_file):
        print("Setting restricted devices...")
        response = self.session.get('http://%s%s' % (self.ip, self.managed_sites_page))
        if response.status_code != 200:  # Page failed to load
            return []  # Return no devices

        restricted_devices = []
        with open(restricted_file, 'r') as f:
            file = csv.DictReader(f)
            for col in file:
                restricted_devices.append(col['host-name'])

        parser = BeautifulSoup(response.content, 'html.parser')  # For quick and easy HTML parsing
        parser = parser.find('table', attrs={'class': 'data', 'id': 'trusted_computers'})  # Find the online devices data
        if not parser:
            raise RuntimeError('Failed to retrieve %s' % self.connectedDevicesPage)
        device_rows = parser('tr')[1: -1]  # Tag list of device table row elements minus header and footer
        
        open('set_restricted_devices.log', 'w').write(str(device_rows))
        path = "http://%s%s" % (self.ip, self.set_restricted_device_form)
        for device in device_rows:
            TrustFlag = {}
            TrustFlag['HostName'] = device.find("td", attrs={'headers': 'device-name'}).text
            if(restricted_devices.count(TrustFlag['HostName']) > 0):
                if(device.find("span").attrs['switch-val'] == 'on'):
                    TrustFlag['IPAddress'] = device.find("td", attrs={'headers': 'IP'}).text
                    TrustFlag['trustFlag'] = 'false'
                    load = { 'TrustFlag': str(TrustFlag).replace('\'','\"') }  
                    self.session.post(path, data=load)
            else:
                if(device.find("span").attrs['switch-val'] == 'off'):
                    TrustFlag['IPAddress'] = device.find("td", attrs={'headers': 'IP'}).text
                    TrustFlag['trustFlag'] = 'true'
                    load = { 'TrustFlag': str(TrustFlag).replace('\'','\"') }  
                    self.session.post(path, data=load)

        return True  # List of (name, ipv4, mac) - each tuple is 1 device

    def getConnectedDevices(self) -> list:
        """Return a list of devices currently connected to this router."""
        response = self.session.get('http://%s%s' % (self.ip, self.connectedDevicesPage))
        if response.status_code != 200:  # Page failed to load
            return []  # Return no devices

        # HTML Elements for device data:
        # <table class="data" ...>
        #   <tbody>
        #     2nd <tr> and on...

        parser = BeautifulSoup(response.content, 'html.parser')  # For quick and easy HTML parsing
        parser = parser.find('table', attrs={'class': 'data'})  # Find the online devices data
        if not parser:
            raise RuntimeError('Failed to retrieve %s' % self.connectedDevicesPage)
        devices = parser('tr')[1:]  # Tag list of device table row elements

        deviceProperties = []
        for device in devices:
            ids = getIdentifiers(device.text)
            if(ids['name'] != 'null'):
                deviceProperties.append(ids)
        return deviceProperties  # List of (name, ipv4, mac) - each tuple is 1 device
    
    def get_managed_sites(self):
        print("Checking existing sites...")
        response = self.session.get('http://%s%s' % (self.ip, self.managed_sites_page))
        if response.status_code != 200:  # Page failed to load
            return []  # Return no devices

        parser = BeautifulSoup(response.content, 'html.parser')  # For quick and easy HTML parsing
        parser = parser.find('table', attrs={'class': 'data', 'summary': "This table lists blocked URLs"})  # Find the online devices data
        if not parser:
            raise RuntimeError('Failed to retrieve %s' % self.connectedDevicesPage)
        sites_rows = parser('tr')[1:]  # Tag list of device table row elements

        sites = []
        start = len('http://')
        for site in sites_rows:
            sites.append(site.find("td", attrs={'headers': 'url'}).text[start:])
        return sites  # List of (name, ipv4, mac) - each tuple is 1 device

    def getToken(self, path) -> str:
        """For port forwarding functions to grab the CSRF token for POST requests."""

        page = self.session.get("http://%s%s" % (self.ip, path)).text
        page = BeautifulSoup(page, 'html.parser')

        element = page.find('input', attrs={'type': 'hidden', 'name': 'csrf_token'})
        return element['value']  # Return the value field of the hidden input for CSRF

    def setPortForwarding(self, toggle: bool) -> bool:
        """Sets the router port forwarding to either Enable or Disable.
        Requires the object to be logged in."""

        load = {'forwarding': 'Enabled' if toggle else 'Disabled',
                'csrf_token': self.getToken(self.portForwardingPath)}
        response = self.session.post('http://%s%s' % (self.ip, self.portForwardingForm), data=load)

        if response.status_code == 200:
            return True
        else:
            print('Set port forwarding: Status code: %d' % response.status_code)
            return False

    def addPortForward(self, serviceName: str, localAddress: int, port: int) -> bool:
        """Add a port forwarding entry to the router. This exposes a port to the internet."""

        load = {'storage_row': -1,
                'csrf_token': self.getToken(self.addForwardPage),
                'common_services': 'other',
                'other_service': serviceName,
                'service_type': 'tcp_udp',
                'server_ip_address_4': str(localAddress),
                'start_port': str(port),
                'end_port': str(port)}
        response = self.session.post('http://%s%s' % (self.ip, self.addForwardForm), data=load)

        if response.status_code == 200:
            return True  # It worked!
        else:
            print('Add port forward: Status code: %d' % response.status_code)
            return False

if __name__ == "__main__":
    r = Router()  # "password" is the default for Xfinity routers
    r.login()  # Login to the router via HTTP
    # r.setManagedSites("firewall.csv")
    r.setRestrictedDevices("restricted_devices.csv")