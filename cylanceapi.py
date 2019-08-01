#DESCRIPTION:
#CyApiHandler encapsulates functionality to access data through Cylance API v2

#IMPORTS
import jwt # PyJWT version 1.5.3 as of the time of authoring.
import uuid
import requests # requests version 2.18.4 as of the time of authoring.
import json
import ConfigParser
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

    #MANDATORY  start:     datetime    e.g.: 2019-07-22T09:09:30Z (ISO Format)
    #MANDATORY  end:       datetime    e.g.: 2019-07-24T18:00:00Z (ISO Format)
    #OPTIONAL   severity:  string      Informational, Low, Medium, High (Case Sensitive)
    #OPTIONAL   device:    string      e.g.: 2217PC70596
    #OPTIONAL   status:    string      New, In Progress, Follow Up, Reviewed, Done, False Positive (Case Sensitive)
    def GetDetectionsCSVList(self, start, end, severity = None, device = None, status = None):
        #Mandatory Parameter Checks
        if not (start and end):
            raise ValueError("Invalid start and/or end datetime")
        
        #Optional Parameter Checks
        if severity and severity not in OPTIONS_SEVERETY:
            raise ValueError("Invalid severity option")
        if status and status not in OPTIONS_STATUS:
            raise ValueError("Invalid status option") 
        
        #Authentication
        #TODO Authenticate only after timeout or if call fails
        
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
        if device:
            payload["device"] = device

        url = DETECTIONS_URL + "/csv"
        response = requests.get(url, headers=headers, params=payload)

        if(int(response.status_code) != 200):
            raise ValueError("Invalid request", str(response.content))
        
        return str(response.content)