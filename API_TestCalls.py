import json
import time
import pandas as pd
from datetime import datetime, timedelta
from cylanceapi import CyApiHandler
import windpapi

#TEST WINDPAPI#####################
testciphertext = windpapi.encryptData("TestString1")
testciphertext.decode('unicode_escape').encode('utf-8')
#print testciphertext

#
plaintext = windpapi.decryptData(testciphertext)
#print plaintext
###################################

Cylance = CyApiHandler()
Cylance.SetConsole(ConsoleId = "ApiTests", ApiId = "98dfba71-511f-4613-8c2a-487a7a36da92", ApiTenantId = "e3a3738f-e186-4ddf-b820-5d7f92493138", ApiSecret = "44db7225-9b96-4b19-a3fd-3c6ed73f15cf", RegionCode = "euc1")

Cylance.GetConsole(ConsoleId = "ApiTests")
#Cylance.WriteConsoleConfig("a", "b", "c", "d", "e")

now = datetime.utcnow()
startDate = now - timedelta(hours=6)

csv_detections = Cylance.GetDetectionsCSVList(startDate.strftime('%Y-%m-%dT%H:%M:%SZ'), now.strftime('%Y-%m-%dT%H:%M:%SZ'))#, detectionType="Internet Browser With Suspicious Parent")
df_detections = Cylance.Csv2DataFrame(csv_detections)
print df_detections

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