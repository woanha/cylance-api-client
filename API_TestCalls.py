import json
from datetime import datetime, timedelta
from cylanceapi import CyApiHandler


Cylance = CyApiHandler(configFilePath = "CyApiConfig.txt")

now = datetime.utcnow()
startDate = now - timedelta(days=2)

csvlist = Cylance.GetDetectionsCSVList(startDate.strftime('%Y-%m-%dT%H:%M:%SZ'), now.strftime('%Y-%m-%dT%H:%M:%SZ'), device = "VIL175NB")
print csvlist


#AUTH_URL = "https://protectapi-euc1.cylance.com/auth/v2/token"
#DETECTIONS_URL = "https://protectapi-euc1.cylance.com/detections/v2"

# def getOpticsDetectionsList(page,size,accessToken):
#     headers = {"Content-Type": "application/json; charset=utf-8","Authorization": "Bearer " + accessToken}
#     response = requests.get(DETECTIONS_URL + "?page=" + str(page) + "&page_size=" + str(size), headers=headers)#, data=json.dumps)
    
#     if response.status_code != 200:
#         # This means something went wrong.
#         raise Exception("API Call not succeeded")

#     return response

# def CylanceAuth():
#     # 30 minutes from now
#     timeout = 1800
#     now = datetime.utcnow()
#     timeout_datetime = now + timedelta(seconds=timeout)
#     epoch_time = int((now - datetime(1970, 1, 1)).total_seconds())
#     epoch_timeout = int((timeout_datetime - datetime(1970, 1, 1)).total_seconds())
#     jti_val = str(uuid.uuid4())

#     claims = {
#     "exp": epoch_timeout,
#     "iat": epoch_time,
#     "iss": "http://cylance.com",
#     "sub": app_id,
#     "tid": tid_val,
#     "jti": jti_val
#     # The following is optional and is being noted here as an example on how one can restrict
#     # the list of scopes being requested
#     # "scp": "policy:create, policy:list, policy:read, policy:update"
#     }
#     encoded = jwt.encode(claims, app_secret, algorithm='HS256')
#     print "auth_token:\n" + encoded + "\n"
#     payload = {"auth_token": encoded}
#     headers = {"Content-Type": "application/json; charset=utf-8"}
#     response = requests.post(AUTH_URL, headers=headers, data=json.dumps(payload))
#     print "http_status_code: " + str(response.status_code)
#     return json.loads(response.text)['access_token']



# accessToken = CylanceAuth()

# if(accessToken):
#     print "Access Token: " + str(accessToken)

# response = getOpticsDetectionsList(1,200,accessToken)
# print json.loads(response.text)