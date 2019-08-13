import json
import time
import pandas as pd
from datetime import datetime, timedelta
from cylanceapi import CyApiHandler


Cylance = CyApiHandler(configFilePath = "CyApiConfig.txt")

now = datetime.utcnow()
startDate = now - timedelta(hours=6)

df_detections = Cylance.GetDetectionsCSVList(startDate.strftime('%Y-%m-%dT%H:%M:%SZ'), now.strftime('%Y-%m-%dT%H:%M:%SZ'), detectionType="Internet Browser With Suspicious Parent")
print df_detections

Cylance.getDetectionDetails(df_detections)

#time.sleep(5)
detectionID = "97614e5e-1e5b-4de8-a89c-b5944b6d5cc8"
detectionDetails = Cylance.getDetection(detectionID)
print detectionDetails