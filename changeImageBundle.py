#!/usr/bin/env python
import requests
import json
import time
###### User Variables

username = 'admin'
password = 'Arista123'
server_list = ['192.168.255.50']
imageToLoad = '4.24.6M'
imageBundleName = 'EOS-4.24.6M_TA_1.16.3-1_v2'

devices_to_upgrade = ['Arista-SP2']

######
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
    response = session.post(url_prefix+'/web/login/logout.do')
    return response.json()

def get_inventory(url_prefix):
    response = session.get(url_prefix+'/cvpservice/inventory/devices?provisioned=true')
    return response.json()

def get_bundleID(url_prefix,imageBundleName):
    response = session.get(url_prefix+'/cvpservice/image/getImageBundles.do?queryparam='+imageBundleName+'&startIndex=0&endIndex=0')
    return response.json()

def remap_Bundle(url_prefix,hostname,nodeMAC,BundleId,imageToLoad):
    tempData = { "data" : [ {
                "info": "Image Bundle Assign: "+hostname,
                "infoPreview": "<b>Image Bundle Assign:</b> "+hostname,
                "action": "associate",
                "nodeType": "imagebundle",
                "nodeId": BundleId,
                "toId": nodeMAC,
                "fromId": "",
                "nodeName": "EOS_"+imageToLoad,
                "fromName": "",
                "toName": hostname,
                "toIdType": "netelement",
                "ignoreNodeId": "",
                "ignoreNodeName": ""
               }]
               }
    response = session.post(url_prefix+'/cvpservice/ztp/addTempAction.do?format=topology&queryParam=&nodeId=root',data=json.dumps(tempData))
    return response.json()

#### Login ####
for server in server_list:
    server1 = 'https://'+server
    print '###### Logging into Server '+server
    login(server1, username, password)
    bundle = get_bundleID(server1,imageBundleName)
    imageBundleID = bundle['data'][0]['key']
    inventory = get_inventory(server1)
    for device in inventory:
         if device['hostname'] in devices_to_upgrade:
             print 'Device '+device['hostname']+' in list to upgrade. Mapping Bundle.'
             output = remap_Bundle(server1,device['hostname'],device['systemMacAddress'],imageBundleID,imageToLoad)
    # refresh and saveTopology after running
    logout(server1)
print 'Done'
