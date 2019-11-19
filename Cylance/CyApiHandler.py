#DESCRIPTION:
#CyApiHandler encapsulates functionality to access data through Cylance API v2

#IMPORTS
import jwt # PyJWT version 1.5.3 as of the time of authoring.
import uuid
import requests # requests version 2.18.4 as of the time of authoring.
import json
import ast
import configparser
import codecs
import base64
import windpapi
import pandas as pd
from io import StringIO
from datetime import datetime, timedelta
from os.path import expanduser
from requests import exceptions

#STATIC VARIABLES
#TODO ADAPT TO INFORMATION IN MEMBERS -> JUST ENDPOINTS
CONSOLECONFIG = '''CyApiConsoles.json'''
AUTH_URL = "https://protectapi-euc1.cylance.com/auth/v2/token"
DETECTIONS_URL = "https://protectapi-euc1.cylance.com/detections/v2"
DEVICES_URL = "https://protectapi-euc1.cylance.com/devices/v2"
RULESETS_URL = "https://protectapi-euc1.cylance.com/rulesets/v2"
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
        except IOError as err: #(errno, strerror):
            errno, strerror = err.args
            if(errno != 2 ): #Other than "No such file or directory"
                raise
            writeNewFile = True
        except ValueError:
            writeNewFile = True
            print ("WARNING: CyApiConsoles.json could not read")
            print ("Console config will be written to new file")

        if writeNewFile:  #file not found -> write new file
            jsonConsoleConfig = {}
            jsonConsoleConfig['Consoles'] = []
            jsonConsoleConfig['Consoles'].append({
                'ConsoleId': ConsoleId,
                'ApiId': ApiId,
                'ApiTenantId': ApiTenantId,
                'ApiSecret': EncryptedApiSecret,
                'ApiUrl': ApiUrl
            })
        elif jsonConsoleConfig: #json file found -> prevent duplicates
            #Check if console already exists
            try:
                console = self.ReadConsole(ConsoleId, jsonConsoleConfig)
            except KeyError:
                print("INFO: Console does not exist in CyApiConsoles.json yet")

            if(console):
                print("Console with ID " + ConsoleId + " already exists. Data not written!")
                return
            
            #No entry found
            jsonConsoleConfig['Consoles'].append({
                'ConsoleId': ConsoleId,
                'ApiId': ApiId,
                'ApiTenantId': ApiTenantId,
                'ApiSecret': EncryptedApiSecret,
                'ApiUrl': ApiUrl
            })
        else: #file found but no json (empty?) -> something went wrong
            raise IOError(79, "Could not write CyApiConsoles.json - file exists but content malformed?!")
        
        with open(jsonPath, 'w') as json_file:
            json.dump(jsonConsoleConfig,json_file)


    def SetConsole(self, ConsoleId, ApiId, ApiTenantId, ApiSecret, RegionCode):
        #Encrypt API Secrect
        #encryptedApiSecret = bytearray()
        encryptedApiSecret = windpapi.encryptData(ApiSecret.encode("utf-8"))
        encryptedApiSecret = base64.b64encode(encryptedApiSecret).decode("utf-8")
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
            print("Existing json could not be read. Malformed CyApiConsoles.json???")
        except IOError as err:
            errno, strerror = err.args
            print("CyApiConsoles.json - I/O error({0}): {1}").format(errno, strerror)

        print("Console with ID {0} written to {1}\\{2}".format(ConsoleId, expanduser('''~'''), CONSOLECONFIG))


    def GetConsole(self, ConsoleId):
        successState = False
        jsonConsoleConfig = None
        jsonConsoleConfig = self.ReadConsoleConfig()

        if(jsonConsoleConfig):
            try:
                console = self.ReadConsole(ConsoleId, jsonConsoleConfig)
            except KeyError:
                print("Console " + ConsoleId  + " could not be found")
                raise
    
        #Read values from json
        try:
            self.tenantID = console["ApiTenantId"]
            self.appID = console["ApiId"]
            self.appSecret = base64.b64decode(console["ApiSecret"])
            self.ApiUrl = console["ApiUrl"]
        except KeyError:
            print("Json keys not found -> malformed CyApiConsoles.json?!")
            return successState

        #Decrypt ApiSecret
        try:
            self.appSecret = windpapi.decryptData(self.appSecret)
            self.appSecret = self.appSecret.decode("utf-8")
        except:
            print("WinDPAPI Error appeared")
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
        payload = {"auth_token": encoded.decode("utf-8")}
        headers = {"Content-Type": "application/json; charset=utf-8"}
        response = requests.post(AUTH_URL, headers=headers, data=json.dumps(payload))
        self.cyToken = json.loads(response.text)['access_token']
        print (self.cyToken)


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
        pageSize = 200
        payload = {}
        jsonContent = None
        numPages = 0
        requestUrlParams = ""
        

        if start:
            requestUrlParams = requestUrlParams + "&start=" + start
        if end:
            requestUrlParams = requestUrlParams + "&end=" + end
        if severity:
            requestUrlParams = requestUrlParams + "&severity=" + severity
        if detectionType:
            requestUrlParams = requestUrlParams + "&detection_type=" + detectionType
        if eventNumber:
            requestUrlParams = requestUrlParams + "&event_number=" + eventNumber
        if device:
            requestUrlParams = requestUrlParams + "&device=" + device
        if status:
            requestUrlParams = requestUrlParams + "&status=" + status
        if sort:
            requestUrlParams = requestUrlParams + "&sort=" + sort


        try:
            self.Authenticate()
        except Exception as error:
            raise IOError("Authentication Fail:", error)
        
        authHeaderString = "Bearer " + self.cyToken
        headers = {"Content-Type": "application/json; charset=utf-8", "Accept": "application/json", "Authorization": authHeaderString}

        url = DETECTIONS_URL + "?page=1&page_size=" + str(pageSize) + requestUrlParams

        try:
            response = requests.get(url, headers=headers, params=payload)
            response.raise_for_status()
        except requests.exceptions.HTTPError as errh:
            print ("HTTP Error:",errh)
            return jsonContent
        except requests.exceptions.ConnectionError as errc:
            print ("Error Connecting:",errc)
            return jsonContent
        except requests.exceptions.Timeout as errt:
            print ("Timeout Error:",errt)
            return jsonContent
        except requests.exceptions.RequestException as err:
            print ("Request Error",err)
            return jsonContent

        #Extract the first page and total page number
        try:
            jsonContent = response.json()
            numPages = jsonContent["total_pages"]
        except ValueError as vError:
            print (vError)
            return None

        #Remove obsolete elements
        try:
            del jsonContent["total_pages"]
            del jsonContent["page_size"]
            del jsonContent["page_number"]
        except ValueError:
            print("Could not remove obsolete elements -> malformed JSON?!?!")

        #Extract the remaining sites, if any
        if numPages < 2: return jsonContent

        for i in range(2, numPages + 1):
            url = DETECTIONS_URL + "?page=" + str(i) + "&page_size=" + str(pageSize) + requestUrlParams
            
            try:
                response = requests.get(url, headers=headers, params=payload)
                response.raise_for_status()
            except requests.exceptions.HTTPError as errh:
                print ("HTTP Error:",errh)
                return jsonContent
            except requests.exceptions.ConnectionError as errc:
                print ("Error Connecting:",errc)
                return jsonContent
            except requests.exceptions.Timeout as errt:
                print ("Timeout Error:",errt)
                return jsonContent
            except requests.exceptions.RequestException as err:
                print ("Request Error",err)
                return jsonContent
                
            try:
                tempContent = response.json()
                jsonContent["page_items"].extend(tempContent["page_items"])
            except ValueError as vError:
                print("Error occured during detection retrieval: RESULT INCOMPLETE!")
                break

        return jsonContent
    

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


    def GetDetection(self, eventID):
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


        
    def DeleteDetection(self, eventID):
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
    def GetDetectionDetails(self, df_detecionslist, commandline = None, user = None, device = None):
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
                jsonDetectionDetails = self.GetDetection(detectionID)
            except ValueError as vError:
                errorCount += 1
                print (vError)
                if errorCount > 5:
                    print("reached limit of maximum errors: ") + str(errorCount)
                    print("aborting ...")
                    return None
                print("continue getting detection details ...")
            except IOError as err:
                errno, strerror = err.args
                print("Getting detection details failed - I/O error({0}): {1}").format(errno, strerror)
                return None

            df_detection = pd.DataFrame(pd.io.json.json_normalize(jsonDetectionDetails))
            df_detection.to_csv('test.csv')


    def GetDetectionRuleSetList(self, description = None, last_modified = None, modified_by_id = None, modified_by_login = None, device_count = None, sort = None ):
        pageSize = 200
        payload = {}
        jsonContent = None
        numPages = 0
        requestUrlParams = ""
        

        if description:
            requestUrlParams = requestUrlParams + "&description=" + description
        if last_modified:
            requestUrlParams = requestUrlParams + "&last_modified=" + last_modified
        if modified_by_id:
            requestUrlParams = requestUrlParams + "&modified_by.id=" + modified_by_id
        if modified_by_login:
            requestUrlParams = requestUrlParams + "&modified_by.login=" + modified_by_login
        if device_count:
            requestUrlParams = requestUrlParams + "&device_count=" + device_count
        if sort:
            requestUrlParams = requestUrlParams + "&sort=" + sort


        try:
            self.Authenticate()
        except Exception as error:
            raise IOError("Authentication Fail:", error)

        
        authHeaderString = "Bearer " + self.cyToken
        headers = {"Content-Type": "application/json; charset=utf-8", "Accept": "application/json", "Authorization": authHeaderString}

        url = RULESETS_URL + "?page=1&page_size=" + str(pageSize) + requestUrlParams

        try:
            response = requests.get(url, headers=headers, params=payload)
            response.raise_for_status()
        except requests.exceptions.HTTPError as errh:
            print ("HTTP Error:",errh)
            return jsonContent
        except requests.exceptions.ConnectionError as errc:
            print ("Error Connecting:",errc)
            return jsonContent
        except requests.exceptions.Timeout as errt:
            print ("Timeout Error:",errt)
            return jsonContent
        except requests.exceptions.RequestException as err:
            print ("Request Error",err)
            return jsonContent

        #Extract the first page and total page number
        try:
            jsonContent = response.json()
            numPages = jsonContent["total_pages"]
        except ValueError as vError:
            print (vError)
            return None

        #Remove obsolete elements
        try:
            del jsonContent["total_pages"]
            del jsonContent["page_size"]
            del jsonContent["page_number"]
        except ValueError:
            print("Could not remove obsolete elements -> malformed JSON?!?!")

        #Extract the remaining sites, if any
        if numPages < 2: return jsonContent

        for i in range(2, numPages + 1):
            url = RULESETS_URL + "?page=" + str(i) + "&page_size=" + str(pageSize) + requestUrlParams
            
            try:
                response = requests.get(url, headers=headers, params=payload)
                response.raise_for_status()
            except requests.exceptions.HTTPError as errh:
                print ("HTTP Error:",errh)
                return jsonContent
            except requests.exceptions.ConnectionError as errc:
                print ("Error Connecting:",errc)
                return jsonContent
            except requests.exceptions.Timeout as errt:
                print ("Timeout Error:",errt)
                return jsonContent
            except requests.exceptions.RequestException as err:
                print ("Request Error",err)
                return jsonContent
                
            try:
                tempContent = response.json()
                jsonContent["page_items"].extend(tempContent["page_items"])
            except ValueError as vError:
                print("Error occured during ruleset retrieval: RESULT INCOMPLETE!")
                break

        return jsonContent


    def GetDetectionRuleSet(self,rulesetId):
        jsonContent = None
        
        try:
            self.Authenticate()
        except Exception as error:
            raise IOError("Authentication Fail:", error)
        
        authHeaderString = "Bearer " + self.cyToken
        headers = {"Content-Type": "application/json; charset=utf-8", "Accept": "application/json", "Authorization": authHeaderString}

        url = RULESETS_URL + "/" + rulesetId

        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
        except requests.exceptions.HTTPError as errh:
            print ("HTTP Error:",errh)
            return None
        except requests.exceptions.ConnectionError as errc:
            print ("Error Connecting:",errc)
            return None
        except requests.exceptions.Timeout as errt:
            print ("Timeout Error:",errt)
            return None
        except requests.exceptions.RequestException as err:
            print ("Request Error",err)
            return None

        try:
            jsonContent = response.json()
        except ValueError as vError:
            print (vError)
            return None

        return jsonContent

    def UpdateDevice(self, deviceUID, deviceName, policyId = None, addZoneIds = None, removeZoneIds = None):
        putSuccess = False
        enoughParams = False
        response = None
        payload = {}

        if (deviceName == None or deviceName == ""):
            raise ValueError("Device Name cannot be empty")
        
        payload["name"] = deviceName

        if policyId:
            payload["policy_id"] = policyId
            enoughParams = True
        if addZoneIds:
            payload["add_zone_ids"] = addZoneIds
            enoughParams = True
        if removeZoneIds:
            payload["remove_zone_ids"] = removeZoneIds
            enoughParams = True

        if not enoughParams:
            print("No parameters to update ... doing nothing")
            return


        try:
            self.Authenticate()
        except Exception as error:
            raise IOError("Authentication Fail:", error)
        
        authHeaderString = "Bearer " + self.cyToken
        headers = {"Content-Type": "application/json; charset=utf-8", "Accept": "application/json", "Authorization": authHeaderString}

        url = DEVICES_URL + "/" + deviceUID

        try:
            response = requests.put(url, headers=headers, data=json.dumps(payload))
        except requests.exceptions.RequestException as error:
            print(error)

        if(int(response.status_code) == 200):
            putSuccess = True

        return putSuccess
    
    
    def CopyDetectionExceptions(self, destRuleSet, srcRuleSet, detectionRule):
        return None

    def AddMemoryExceptionToPolicies(self, policies, exceptionList):
        return None

    