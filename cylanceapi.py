#DESCRIPTION:
#CyApiHandler encapsulates functionality to access data through Cylance API v2

#IMPORTS
import jwt # PyJWT version 1.5.3 as of the time of authoring.
import uuid
import requests # requests version 2.18.4 as of the time of authoring.
import json
import ast
import ConfigParser
import codecs
import windpapi
import pandas as pd
from io import StringIO
from datetime import datetime, timedelta
from os.path import expanduser


#STATIC VARIABLES
CONSOLECONFIG = "CyApiConsoles.json"
AUTH_URL = "https://protectapi-euc1.cylance.com/auth/v2/token"
DETECTIONS_URL = "https://protectapi-euc1.cylance.com/detections/v2"
POLICIES_URL = "https://protectapi-euc1.cylance.com/policies/v2"
OPTIONS_SEVERETY = ['Informational', 'Low', 'Medium', 'High']
OPTIONS_STATUS = ['New', 'In Progress', 'Follow Up', 'Reviewed', 'Done', 'False Positive']

class CyApiHandler:
        
    def __init__(self,tenantID = None, appID = None, appSecret = None, configFilePath = None, regionCode = None):
        
        if (configFilePath and configFilePath != ""):
            self.tenantID, self.appID, self.appSecret = self.ReadConfig(configFilePath)
        elif(tenantID and appID and appSecret):
            self.tenantID = tenantID
            self.appID = appID
            self.appSecret = appSecret
            self.regionCode = regionCode
        else:
            self.tenantID = ""
            self.appID = ""
            self.appSecret = ""
            self.regionCode = ""

        self.AuthUrl = ""
        self.DetectionsUrl = ""
        self.PoliciesUrl = ""
        self.cyToken = ""     


    #DEPRECATED: Use SetConsole/GetConsole 
    def ReadConfig(self, configFilePath):
        if not configFilePath or configFilePath == "":
            raise ValueError("Invalid config file path")

        configParser = ConfigParser.RawConfigParser()   
        configParser.read(configFilePath)

        tid_val = configParser.get('AUTHENTICATION', 'tid_val')
        app_id = configParser.get('AUTHENTICATION', 'app_id')
        app_secret = configParser.get('AUTHENTICATION', 'app_secret')

        return tid_val, app_id, app_secret


    def ReadConsole(self, consoleId, jsonConsoleConfig):
        for console in jsonConsoleConfig['Consoles']:
                try:
                    if console['ConsoleId'] == consoleId:
                        return console
                except KeyError:
                    raise

        return None


    def ReadConsoleConfig(self):
        config = None
        jsonPath = expanduser("~") + "\\" + CONSOLECONFIG
        with open(jsonPath, 'r') as json_file:
            config = json.load(json_file)
        return config

    
    def WriteConsoleConfig(self, ConsoleId, ApiId, ApiTenantId, EncryptedApiSecret, ApiUrl):
        writeNewFile = False
        jsonConsoleConfig = None
        jsonPath = expanduser("~") + "\\" + CONSOLECONFIG

        try:        
            jsonConsoleConfig =self.ReadConsoleConfig()
        except IOError as (errno, strerror):
            if(errno is not 2 ): #Other than "No such file or directory"
                raise
            writeNewFile = True
        except ValueError:
            writeNewFile = True
            print "WARNING: CyApiConsoles.json could not read"
            print "Console config will be written to new file"

        if writeNewFile:  #file not found -> write new file
            jsonConsoleConfig = {}
            jsonConsoleConfig['Consoles'] = []
            jsonConsoleConfig['Consoles'].append({
                'ConsoleId': ConsoleId,
                'ApiId': ApiId,
                'ApiTenantId': ApiTenantId,
                'ApiSecret': EncryptedApiSecret,#.decode('unicode_escape').encode('utf-8'),
                'ApiUrl': ApiUrl
            })
        elif jsonConsoleConfig: #json file found -> prevent duplicates
            #Check if console already exists
            try:
                console = self.ReadConsole(ConsoleId, jsonConsoleConfig)
            except KeyError:
                print "INFO: Console does not exist in CyApiConsoles.json yet"

            if(console):
                print "Console with ID " + ConsoleId + " already exists. Data not written!"
                return
            
            #No entry found
            jsonConsoleConfig['Consoles'].append({
                'ConsoleId': ConsoleId,
                'ApiId': ApiId,
                'ApiTenantId': ApiTenantId,
                'ApiSecret': EncryptedApiSecret,#.decode('unicode_escape').encode('utf-8'),
                'ApiUrl': ApiUrl
            })
        else: #file found but no json (empty?) -> something went wrong
            raise IOError(79, "Could not write CyApiConsoles.json - file exists but content malformed?!")
        
        with open(jsonPath, 'w') as json_file:
            json.dump(jsonConsoleConfig,json_file)


    def SetConsole(self, ConsoleId, ApiId, ApiTenantId, ApiSecret, RegionCode):
        #Encrypt API Secrect
        encryptedApiSecret = bytearray()
        encryptedApiSecret = windpapi.encryptData(ApiSecret)
        encryptedApiSecret = encryptedApiSecret.encode('base64')
        ApiUrl = ""

        #Generate API Url based on region code
        if (RegionCode == "apne1" or RegionCode == "au" or RegionCode == "euc1" or RegionCode == "sae1"):
            ApiUrl = "https://protect-" + RegionCode + ".cylance.com"
        elif (RegionCode == "us-gov"):
            ApiUrl = "https://protectapi-" + RegionCode + ".cylance.com"
        else:
            raise ValueError("Please specify valid region code: apne1, au, euc1, sae1, us-gov")

        try:
            self.WriteConsoleConfig(ConsoleId, ApiId, ApiTenantId, encryptedApiSecret, ApiUrl)
        except KeyError:
            print "Existing json could not be read. Malformed CyApiConsoles.json???"
        except IOError as (errno, strerror):
            print "CyApiConsoles.json - I/O error({0}): {1}".format(errno, strerror)

        print "Console with ID " + ConsoleId + " written to " + expanduser("~") + "\\" + CONSOLECONFIG


    def GetConsole(self, ConsoleId):
        successState = False
        jsonConsoleConfig = None
        jsonConsoleConfig = self.ReadConsoleConfig()

        if(jsonConsoleConfig):
            try:
                console = self.ReadConsole(ConsoleId, jsonConsoleConfig)
            except KeyError:
                print "Console " + ConsoleId  + " could not be found"
                raise
    
        #Read values from json
        try:
            self.tenantID = console["ApiTenantId"]
            self.appID = console["ApiId"]
            self.appSecret = console["ApiSecret"].decode('base64')
            self.ApiUrl = console["ApiUrl"]
        except KeyError:
            print "Json keys not found -> malformed CyApiConsoles.json?!"
            return successState
        

        #TESTS
        #test1 = self.appSecret.decode('utf-8')

        #self.appSecret = self.appSecret.encode('unicode_escape')#.decode('utf-8')
        #self.appSecret = self.appSecret.decode('utf-8')

        #Decrypt ApiSecret
        try:
            self.appSecret = windpapi.decryptData(self.appSecret)
        except:
            print "WinDPAPI Error appeared"
            raise

        self.AuthUrl = self.ApiUrl + "/auth/v2/token"
        self.DetectionsUrl = self.ApiUrl + "/detections/v2"
        self.PoliciesUrl = self.ApiUrl + "/policies/v2"
        self.cyToken = ""     

        successState = True

        return successState


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
        payload = {"auth_token": encoded}
        headers = {"Content-Type": "application/json; charset=utf-8"}
        response = requests.post(AUTH_URL, headers=headers, data=json.dumps(payload))
        self.cyToken = json.loads(response.text)['access_token']
        print self.cyToken


    #RETURNS JSON
    #OPTIONAL   last            digit       returns the last n detections
    #MANDATORY  start:          datetime    e.g.: 2019-07-22T09:09:30Z (ISO Format)
    #MANDATORY  end:            datetime    e.g.: 2019-07-24T18:00:00Z (ISO Format)
    #OPTIONAL   severity:       string      Informational, Low, Medium, High (Case Sensitive)
    #OPTIONAL   detectionType:  string      Name of detection, e.g. Internet Browser With Suspicious Parent
    #OPTIONAL   eventNumber:    string      This is the PhoneticId in the API and Detection ID in the Console (IF SET OTHER FILTERS ARE IGNORED)
    #OPTIONAL   device:         string      e.g.: 2217PC70596
    #OPTIONAL   status:         string      New, In Progress, Follow Up, Reviewed, Done, False Positive (Case Sensitive)
    #OPTIONAL   sort:           string      Sort by the following fields (adding "-" in front of the value denotes descending order)
                                                            # Severity
                                                            # OccurrenceTime
                                                            # Status
                                                            # Device
                                                            # PhoneticId
                                                            # Description
                                                            # ReceivedTime
    def GetDetections(self, last = None, start = None, end = None, severity = None, detectionType = None, eventNumber = None, device = None, status = None, sort = None):
        #Check input params and generate payload
        #return if no params passed
        paramCount = 0
        pageSize = 200
        payload = {}

        if start:
            payload["start"] = start
            paramCount += 1
        if end:
            payload["end"] = end
            paramCount += 1
        if severity:
            payload["severity"] = severity
            paramCount += 1
        if detectionType:
            payload["detectionType"] = detectionType
            paramCount += 1
        if eventNumber:
            payload["eventNumber"] = eventNumber
            paramCount += 1
        

        if paramCount == 0:
            raise ValueError("No parameters passed")

        try:
            self.Authenticate()
        except Exception as error:
            raise IOError("Authentication Fail:", error)
        
        return None
    

    #RETURNS CSV
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
        errorCount = 0

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


    #TODO AddMemoryExceptionToPolicies(policyStringArray) wildcard for all poices
    def AddMemoryExceptionToPolicies(self, policies):
        return None