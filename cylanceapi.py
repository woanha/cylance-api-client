#DESCRIPTION:
#CyApiHandler encapsulates functionality to access data through Cylance API v2

#IMPORTS
import jwt # PyJWT version 1.5.3 as of the time of authoring.
import uuid
import requests # requests version 2.18.4 as of the time of authoring.
import json
import ast
import ConfigParser
import pandas as pd
from io import StringIO
from datetime import datetime, timedelta


#STATIC VARIABLES
AUTH_URL = "https://protectapi-euc1.cylance.com/auth/v2/token"
DETECTIONS_URL = "https://protectapi-euc1.cylance.com/detections/v2"
OPTIONS_SEVERETY = ['Informational', 'Low', 'Medium', 'High']
OPTIONS_STATUS = ['New', 'In Progress', 'Follow Up', 'Reviewed', 'Done', 'False Positive']

class CyApiHandler:
    
    def ReadConfig(self, configFilePath):
        if not configFilePath or configFilePath == "":
            raise ValueError("Invalid config file path")

        configParser = ConfigParser.RawConfigParser()   
        configParser.read(configFilePath)

        tid_val = configParser.get('AUTHENTICATION', 'tid_val')
        app_id = configParser.get('AUTHENTICATION', 'app_id')
        app_secret = configParser.get('AUTHENTICATION', 'app_secret')

        return tid_val, app_id, app_secret
    
    def __init__(self,tenantID = None, appID = None, appSecret = None, configFilePath = None):
        
        if (configFilePath and configFilePath != ""):
            self.tenantID, self.appID, self.appSecret = self.ReadConfig(configFilePath)
        else:
            self.tenantID = tenantID
            self.appID = appID
            self.appSecret = appSecret

        self.cyToken = ""     
        
    def Csv2DataFrame(self, csv):
        if not csv:
            return None
        df = pd.read_csv(StringIO(csv.decode('unicode-escape')), sep = ",")
        return df

    
    #TODO Authenticate only after timeout or if call fails
    def Authenticate(self):
         # 30 minutes from now
        timeout = 1800
        now = datetime.utcnow()
        timeout_datetime = now + timedelta(seconds=timeout)
        epoch_time = int((now - datetime(1970, 1, 1)).total_seconds())
        epoch_timeout = int((timeout_datetime - datetime(1970, 1, 1)).total_seconds())
        jti_val = str(uuid.uuid4())

        claims = {
        "exp": epoch_timeout,
        "iat": epoch_time,
        "iss": "http://cylance.com",
        "sub": self.appID,
        "tid": self.tenantID,
        "jti": jti_val
        # The following is optional and is being noted here as an example on how one can restrict
        # the list of scopes being requested
        # "scp": "policy:create, policy:list, policy:read, policy:update"
        }
        encoded = jwt.encode(claims, self.appSecret, algorithm='HS256')
        #print "auth_token:\n" + encoded + "\n"
        payload = {"auth_token": encoded}
        headers = {"Content-Type": "application/json; charset=utf-8"}
        response = requests.post(AUTH_URL, headers=headers, data=json.dumps(payload))
        #print "http_status_code: " + str(response.status_code)
        self.cyToken = json.loads(response.text)['access_token']
        print self.cyToken

    #RETURNS PANDAS DATAFRAME
    #MANDATORY  start:          datetime    e.g.: 2019-07-22T09:09:30Z (ISO Format)
    #MANDATORY  end:            datetime    e.g.: 2019-07-24T18:00:00Z (ISO Format)
    #OPTIONAL   detectionType:  string      Name of detection, e.g. Internet Browser With Suspicious Parent
    #OPTIONAL   severity:       string      Informational, Low, Medium, High (Case Sensitive)
    #OPTIONAL   device:         string      e.g.: 2217PC70596
    #OPTIONAL   status:         string      New, In Progress, Follow Up, Reviewed, Done, False Positive (Case Sensitive)
    def GetDetectionsCSVList(self, start, end, detectionType = None, severity = None, device = None, status = None):
        #Mandatory Parameter Checks
        if not (start and end):
            raise ValueError("Invalid start and/or end datetime")
        
        #Optional Parameter Checks
        if severity and severity not in OPTIONS_SEVERETY:
            raise ValueError("Invalid severity option")
        if status and status not in OPTIONS_STATUS:
            raise ValueError("Invalid status option") 

        try:
            self.Authenticate()
        except Exception as error:
            raise IOError("Authentication Fail:", error)

        authHeaderString = "Bearer " + self.cyToken
        headers = {"Content-Type": "application/json; charset=utf-8", "Accept": "application/json", "Authorization": authHeaderString}
        payload = {"start": start, "end": end}

        if severity:
            payload["severity"] = severity
        if status:
            payload["status"] = status
        if detectionType:
            payload["detection_type"] = detectionType
        if device:
            payload["device"] = device

        url = DETECTIONS_URL + "/csv"
        response = requests.get(url, headers=headers, params=payload)

        if(int(response.status_code) != 200):
            raise ValueError("Invalid request", str(response.content))
        
        #df = pd.read_csv(StringIO(response.content.decode('unicode-escape')), sep = ",")
        return response.content


    def getDetection(self, eventID):
        if not eventID or eventID == "":
            raise ValueError("Invalid detection ID")

        try:
            self.Authenticate()
        except Exception as error:
            raise IOError("Authentication Fail:", error)

        authHeaderString = "Bearer " + self.cyToken
        headers = {"Content-Type": "application/json; charset=utf-8", "Accept": "application/json", "Authorization": authHeaderString}
        url = DETECTIONS_URL + "/" + eventID + "/details"

        response = requests.get(url, headers=headers)

        if(int(response.status_code) != 200):
            raise ValueError("Invalid request", str(response.content))
        
        return response.json()


        
    def deleteDetection(self, eventID):
        if not eventID or eventID == "":
            raise ValueError("Invalid detection ID")

        try:
            self.Authenticate()
        except Exception as error:
            raise IOError("Authentication Fail:", error)

        authHeaderString = "Bearer " + self.cyToken
        headers = {"Content-Type": "application/json; charset=utf-8", "Accept": "application/json", "Authorization": authHeaderString}

        url = DETECTIONS_URL + "/" + eventID

        response = requests.delete(url, headers=headers)

        if(int(response.status_code) != 200):
            raise ValueError("Invalid request", str(response.content))
        
        return response.json()

    #MANDATORY  df_detecionslist:   pandas.DataFrame    Output from GetDetectionsCSVList
    #TODO: Optional parameters for conditions, like commandline etc
    def getDetectionDetails(self, df_detecionslist, commandline = None, user = None, device = None):
        errorCount = 0;

        if not isinstance(df_detecionslist, pd.DataFrame):
            raise ValueError("Parameter is not of type pd.Dataframe")
        
        try:
            self.Authenticate()
        except Exception as error:
            raise IOError("Authentication Fail:", error)

        for index, row in df_detecionslist.iterrows():
            detectionID = row['Id']

            try:
                jsonDetectionDetails = self.getDetection(detectionID)
            except ValueError as vError:
                errorCount += 1
                print vError
                if errorCount > 5:
                    print "reached limit of maximum errors: " + str(errorCount)
                    print "aborting ..."
                    return None
                print "continue getting detection details ..."
            except IOError as ioError:
                print ioError
                print "getting detection details failed"
                return None

            df_detection = pd.DataFrame(pd.io.json.json_normalize(jsonDetectionDetails))
            df_detection.to_csv('test.csv')