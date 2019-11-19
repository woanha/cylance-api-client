import json
import time
import pandas as pd
from datetime import datetime, timedelta
from Cylance import CyApiHandler
#import windpapi


####-TEST WINDPAPI------------------------------------------------------------------------------------
#testPlainText = '''TESTSTRING'''
#testCipherText = ''''''
#testOutput = ''''''
#
#testCipherText = windpapi.encryptData(testPlainText.encode("utf-8"))
#testOutput = windpapi.decryptData(testCipherText)
#print(type(testOutput))
####-----------------------------------------------------------------------------------------------

Cylance = CyApiHandler.CyApiHandler()
#Cylance.SetConsole(ConsoleId = "ApiTests", ApiId = "98dfba71-511f-4613-8c2a-487a7a36da92", ApiTenantId = "e3a3738f-e186-4ddf-b820-5d7f92493138", ApiSecret = "44db7225-9b96-4b19-a3fd-3c6ed73f15cf", RegionCode = "euc1")

Cylance.GetConsole(ConsoleId = "ApiTests")

####-TEST GetDetectionsCSVList()------------------------------------------------------------------------
now = datetime.utcnow()
startDate = now - timedelta(hours=6)
csv_detections = Cylance.GetDetectionsCSVList(startDate.strftime('%Y-%m-%dT%H:%M:%SZ'), now.strftime('%Y-%m-%dT%H:%M:%SZ'))#, detectionType="Internet Browser With Suspicious Parent")
df_detections = Cylance.Csv2DataFrame(csv_detections)
print (df_detections)
####----------------------------------------------------------------------------------------------------

####-TEST UpdateDevice()-----------------------------------------------------------------------
#Cylance.UpdateDevice(deviceName = "2126PC63383", deviceUID = "f188b93f-7b24-4e56-b069-59bc0d7642d3", policyId = "e8a7168a-f2d9-4507-873a-84c402265036")
####----------------------------------------------------------------------------------------------------


####-TEST GetDetectionRuleSetList()-----------------------------------------------------------------------
# jsonRuleSetList = Cylance.GetDetectionRuleSetList(description = None, last_modified = None, modified_by_id = None, modified_by_login = None, device_count = None, sort = None)

# if (not jsonRuleSetList): exit()

# for item in jsonRuleSetList['page_items']:
#     id = item['id']
#     jsonRuleSet = Cylance.GetDetectionRuleSet(rulesetId = id)
#     filename = jsonRuleSet['name'].replace('/', '_') + '.json'
#     with open(filename, 'w') as jsonFile:
#         json.dump(jsonRuleSet, jsonFile)
####----------------------------------------------------------------------------------------------------

#with open("rulesetlist.json", "w") as f:
#    json.dump(jsonRuleSetList, f)    

####-TEST GetDetections()---------------------------------------------------------------------------------
detectionType="Suspicious OS Process Owner"
jsonDetections = Cylance.GetDetections(start = (now-timedelta(days=5)).strftime('%Y-%m-%dT%H:%M:%SZ'), end = now.strftime('%Y-%m-%dT%H:%M:%SZ'), severity=None, status=None, sort=None, detectionType="Suspicious OS Process Owner" )

with open("data.json", "w") as f:
   json.dump(jsonDetections, f)
####-------------------------------------------------------------------------------------------------------


####-Create list of hosts with potential certificate issue--------------------------------------------------------------------
cert_issue_devices = set()
instProcUid = ""
instImageUid = ""
for item in jsonDetections["page_items"]:
   detectionDetails = Cylance.GetDetection(eventID = item["Id"])
   AOI = detectionDetails["ArtifactsOfInterest"]
   for artifact, value in AOI.items():
      for element in value:
         if element['Source'] == 'Instigating Process':
            instProcUid = element['Artifact']['Uid']
            break

   
   associatedArtifacts = detectionDetails["AssociatedArtifacts"]
   for artifact in associatedArtifacts:
      if artifact["Uid"] == instProcUid:
         instImageUid = artifact["PrimaryImage"]["Uid"]
         break
   
   for artifact in associatedArtifacts:
      if artifact["Uid"] == instImageUid:
         fileSignatureJson = json.loads(artifact["FileSignatureJson"])
         signatureStatus = fileSignatureJson["SignatureStatus"]
         if signatureStatus == "IssuerSignatureMissing":
            cert_issue_devices.add((item["Device"]["Name"],item["Device"]["CylanceId"]))
            break;

with open(now.strftime('%Y%m%d%H%M%S')+'cert_issue_hosts.txt', 'w') as f:
   for val in cert_issue_devices:
      line = ','.join(str(x) for x in val)
      f.write(line + '\n')

for val in cert_issue_devices:
   deviceUpdated = Cylance.UpdateDevice(deviceName = val[0], deviceUID = val[0], policyId = "e8a7168a-f2d9-4507-873a-84c402265036")
   if not deviceUpdated:
      print (val[0] + "not updated")

   #Cylance.UpdateDevice(deviceName = "2126PC63383", deviceUID = "f188b93f-7b24-4e56-b069-59bc0d7642d3", policyId = "e8a7168a-f2d9-4507-873a-84c402265036")
####-----------------------------------------------------------------------------------------


#print "Number of hosts: "  + str(len(potential_prod_devices))
#print potential_prod_devices
#Cylance.GetDetections(start = startDate.strftime('%Y-%m-%dT%H:%M:%SZ'), end = now.strftime('%Y-%m-%dT%H:%M:%SZ'))

#result = Cylance.deleteDetection("b42906b0-ae1f-45d9-9f55-4b919b90504c")
#print result


#df_detections.to_csv('detections.csv')

#Cylance.getDetectionDetails(df_detections) #return a list of jsons?

#Cylance.deleteDetection("0815a5d0-feac-4187-89f3-84f407dce359")

#time.sleep(5)
#detectionID = "97614e5e-1e5b-4de8-a89c-b5944b6d5cc8"
#detectionDetails = Cylance.getDetection(detectionID)
#print detectionDetails