import datetime
import requests
import json
import commands
import re
import os

username = 'cvpadmin'
password = 'Arista'
server1 = 'https://192.168.255.50'

"""
Requirements:
  - Load this file onto CVP itself, and update the username, password, and server1 IP to
  reference your CVP server information.
  - Configure TerminAttr to stream to CVP, and also configure the 'cvsourceip' daemon attribute
  for the loopback you want to manage through, eg:
      {options ... -cvsourceip=192.0.2.1} as an example if Loopback0 is 192.0.2.1/32.
  - Run script from CVP bash shell using 'python provision.py'
  - Note for switches in ZTP mode change the ZtpMode flag to true from false when applying the metadata
"""

connect_timeout = 10
headers = {"Accept": "application/json",
           "Content-Type": "application/json"}
requests.packages.urllib3.disable_warnings()
session = requests.Session()

def login(url_prefix, username, password):
    authdata = {"userId": username, "password": password}
    headers.pop('APP_SESSION_ID', None)
    response = session.post(url_prefix+'/web/login/authenticate.do', data=json.dumps(authdata),
                            headers=headers, timeout=connect_timeout,
                            verify=False)
    cookies = response.cookies
    headers['APP_SESSION_ID'] = response.json()['sessionId']
    if response.json()['sessionId']:
        return response.json()['sessionId']

def logout(url_prefix):
    response = session.post(url_prefix+'/web/login/authenticate.do')
    return response.json()

def get_inventory(url_prefix):
    response = session.get(url_prefix+'/cvpservice/inventory/devices?provisioned=false')
    return response.json()

def parse_inventory(url_prefix):
    devices = {}
    login(server1, username, password)
    inventory = get_inventory(server1)
    for device in inventory:
        if not device['status'] and not device['parentContainerKey']:
          try:
            mgmtIP = get_mgmt_ip(device['serialNumber'])
            devices.update({device['hostname']: {'serial': device['serialNumber'],
                'ipAddr': mgmtIP, 'macAddr': device['systemMacAddress']}})
          except:
            print device['hostname'], "wasn't added as it does not have the cvsourceip set"
    return devices

def apply_metadata(ipAddr,macAddr):
    currentTime = datetime.datetime.now()
    nanotimestamp = str(currentTime.isoformat('T'))+'000Z'
    os.system("""/cvpi/tools/apish publish -d cvp -t %s -p '[{"key":"inventory"}, {"key":"deviceMetadata"}]' --update '{"value": {"IpAddress": "%s", "ZtpMode": false}, "key": "%s"}'""" % (nanotimestamp, ipAddr, macAddr))
    return 'metadata applied to '+ipAddr

def apply_provisioning(serialNumber):
    currentTime = datetime.datetime.now()
    nanotimestamp = str(currentTime.isoformat('T'))+'000Z'
    os.system("""/cvpi/tools/apish publish -d cvp -t %s -p '[{"key":"inventory"}, {"key":"requests"}]' --update '{"value": {"userName": "cvp system", "containerKey": "undefined_container"}, "key": {"requestType": "mapToContainer", "serialNumber": "%s"}}'""" % (nanotimestamp, serialNumber))
    return 'provisioning applied to '+serialNumber

def get_mgmt_ip(serialNumber):
    runningConfig = commands.getstatusoutput("""/cvpi/tools/apish get -d %s -p /Config/running/lines""" % serialNumber)
    premgmtIP = re.findall(r"cvsourceip=[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}",str(runningConfig))
    mgmtIP = premgmtIP[0].split('=')[1]
    return mgmtIP

def main():
    login(server1,username,password)
    parsed = parse_inventory(server1)
    logout(server1)
    if parsed:
        print 'Adding the following devices to Provisioning. Type "yes" to continue.'
        for item in parsed.keys():
            print '-------'
            print item
            print parsed[item]['serial']
            print parsed[item]['ipAddr']
            print parsed[item]['macAddr']
        confirmed = False
        while confirmed == False:
            reply = str(raw_input('Continue? (yes/no): ')).lower().strip()
            if reply == 'yes':
                confirmed = True
                for item in parsed.keys():
                    apply_metadata(parsed[item]['ipAddr'],parsed[item]['macAddr'])
                    apply_provisioning(parsed[item]['serial'])
                    print 'Complete. All items added.'
            if reply == 'no':
                exit()
    else:
        print 'No devices to add...'


if __name__ == "__main__":
  main()
