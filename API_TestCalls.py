import json
import time
import pandas as pd
from datetime import datetime, timedelta
from cylanceapi import CyApiHandler


Cylance = CyApiHandler(configFilePath = "CyApiConfig.txt")

now = datetime.utcnow()
startDate = now - timedelta(hours=6)

csv_detections = Cylance.GetDetectionsCSVList(startDate.strftime('%Y-%m-%dT%H:%M:%SZ'), now.strftime('%Y-%m-%dT%H:%M:%SZ'), detectionType="Internet Browser With Suspicious Parent")
df_detections = Cylance.Csv2DataFrame(csv_detections)
print df_detections
#df_detections.to_csv('detections.csv')

#Cylance.getDetectionDetails(df_detections) #return a list of jsons?

Cylance.deleteDetection("0815a5d0-feac-4187-89f3-84f407dce359")

#time.sleep(5)
#detectionID = "97614e5e-1e5b-4de8-a89c-b5944b6d5cc8"
#detectionDetails = Cylance.getDetection(detectionID)
#print detectionDetails