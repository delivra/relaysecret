import boto3
import sys
import hashlib
import time
import secrets
import os
import traceback
import json
import re
import datetime
import urllib.request
from urllib.parse import urlsplit, urlunsplit, parse_qs
from botocore.client import Config
import hmac
import hashlib
from typing import Dict, Optional, Union

# Change BUCKET_NAME to your bucket name and
# KEY_NAME to the name of a file in the directory where you'll run the curl command.
bktUS = os.environ['BUCKETNAME']
bktAU = os.environ['BUCKETNAME_AU']
bktEU = os.environ['BUCKETNAME_EU']
bkt = bktUS
awsregionUS = "us-west-1"
awsregionAU = "ap-southeast-2"
awsregionEU = "eu-central-1"
awsregion = awsregionUS

seed = os.environ['SEED']
appdomain = os.environ['APP_DOMAIN']
appurl = os.environ['APPURL']
vtapikey = os.environ['VTAPIKEY']
hmacsecret = os.environ['HMACSECRET']
signing_secret = os.environ['SLACK_SIGNING_SECRET']

# Set the max object size.. (200mb)
maxobjectsize = 200000000

class Clock:
    @staticmethod
    def now() -> float:
        return time.time()


# From https://github.com/slackapi/python-slack-sdk/blob/2a4487c81fa95d1cb07a3d916887ac10d67d79ab/slack/signature/verifier.py
class SignatureVerifier:
    def __init__(self, signing_secret: str, clock: Clock = Clock()):
        """Slack request signature verifier
        Slack signs its requests using a secret that's unique to your app.
        With the help of signing secrets, your app can more confidently verify
        whether requests from us are authentic.
        https://api.slack.com/authentication/verifying-requests-from-slack
        """
        self.signing_secret = signing_secret
        self.clock = clock


    def is_valid(
        self,
        body: Union[str, bytes],
        timestamp: str,
        signature: str,
    ) -> bool:
        """Verifies if the given signature is valid"""
        if timestamp is None or signature is None:
            return False

        if abs(self.clock.now() - int(timestamp)) > 60 * 5:
            return False

        calculated_signature = self.generate_signature(timestamp=timestamp, body=body)
        if calculated_signature is None:
            return False
        return hmac.compare_digest(calculated_signature, signature)

    def generate_signature(
        self, *, timestamp: str, body: Union[str, bytes]
    ) -> Optional[str]:
        """Generates a signature"""
        if timestamp is None:
            return None
        if body is None:
            body = ""
        if isinstance(body, bytes):
            body = body.decode("utf-8")

        format_req = str.encode(f"v0:{timestamp}:{body}")
        encoded_secret = str.encode(self.signing_secret)
        request_hash = hmac.new(encoded_secret, format_req, hashlib.sha256).hexdigest()
        calculated_signature = f"v0={request_hash}"
        return calculated_signature

def getposturl(expiretime):
    try:
        exp=int(expiretime)
    except:
        exp=10
    s3 = boto3.client('s3',config=Config(region_name=awsregion, signature_version='s3v4'))
    fields = {
            "acl": "private",
            }
    conditions = [
        {"acl": "private"},
        {"content-type":"text/plain"},
        ["content-length-range", 1, maxobjectsize],
        ["starts-with", "$x-amz-meta-tag", ""]
    ]

    # sha256 of seed, random bits and time just to make sure it is unique ;).
    random = seed+str(time.time())+str(secrets.randbits(256))
    h = hashlib.sha256()
    h.update(random.encode("utf-8"))
    keyname = "{exp}day/{sha256}".format(exp=exp,sha256=h.hexdigest())

    return s3.generate_presigned_post(Bucket=bkt,Key=keyname,Fields=fields,Conditions=conditions)

def getshareurl(event):
    # Verify slack payload
    if signing_secret == "none":
        raise Exception('No signing key')

    body = event["body"]
    timestamp = event["headers"]["X-Slack-Request-Timestamp"]
    signature = event["headers"]["X-Slack-Signature"]

    verifier = SignatureVerifier(signing_secret=signing_secret)
    if not verifier.is_valid(body, timestamp, signature):
        print(f"Received event with bad signature:\n{event}")
        raise Exception('Bad signature')

    # Extract custom expiration from text (if specified)
    expiredays = 1
    expiredaysmatch = re.search('^\s*(?P<expiredays>[1-9][0-9]?)\s*$', parse_qs(body).get('text', [''])[0])
    if expiredaysmatch:
        expiredays = int(expiredaysmatch.group('expiredays'))

    # Set limits
    if expiredays > 10:
        expiredays = 10
    if expiredays < 1:
        expiredays = 1

    # Generate signed url
    key = hmacsecret.encode('utf-8')
    exp = int(datetime.datetime.now().timestamp() + 3600 * 24 * expiredays)
    data = str(exp).encode('utf-8')
    sig = hmac.new(key=key, msg=data, digestmod=hashlib.sha256).hexdigest().lower()
    url = f'https://{appdomain}/encrypt.html?exp={exp}.{sig}'

    # Format slack message
    return {
        "response_type": "ephemeral",
        "text": f'*Link:* {url}\n *Expire in: {expiredays} days*'
    }

def getobj(key):
    s3 = boto3.client('s3', config=Config(region_name=awsregion, signature_version='s3v4'))
    response = s3.head_object(Bucket=bkt, Key=key)

    expstr = response["Expiration"].split('"')[1].split(',')[1].strip()
    exp = datetime.datetime.strptime(expstr,'%d %b %Y %H:%M:%S %Z')

    # LastModified already comes as datetime object, converting both to epoch and add the
    # extra neccessary seconds for expiration is much easier/quicker.
    expiredays = int(re.search("[0-9]+",key)[0])
    exactepochexpiretime = response["LastModified"].timestamp()+3600*24*expiredays
    currentepochtime = datetime.datetime.now().timestamp()

    print("{} compare with {}".format(currentepochtime,exactepochexpiretime))
    # When an object is expired, it is put on a queue to get deleted by AWS.
    # This obviously might take sometimes so just incase AWS drops the ball, we will remove the file anyway.
    if (exactepochexpiretime < currentepochtime):
        print("Object was expired, Deleting it now")
        deleteobj(key)
        return None

    objsize = response['ContentLength']
    objname = ""
    try:
        filemetadata = json.loads(response['ResponseMetadata']['HTTPHeaders']['x-amz-meta-tag'])
        objname = filemetadata["name"]
    except:
        objname = "unknown-file-name"
    return {
        "objsize":objsize,
        "objname": objname,
        "signedurl": s3.generate_presigned_url(
            'get_object',
            Params={'Bucket': bkt,
            'Key': key},
            ExpiresIn=3600
        )
    }

def deleteobj(key):
    s3 = boto3.client('s3', config=Config(region_name=awsregion, signature_version='s3v4'))
    return s3.delete_object(
        Bucket=bkt,
        Key=key)

def checkvirus(filehash):
    if (vtapikey == "none"):
        return {'status_code':404}
    BASEURL = "https://www.virustotal.com/vtapi/v2/"
    VERSION = "0.0.9"
    API_KEY = vtapikey
    headers = {
            "Accept-Encoding": "identity",
            "User-Agent": f"gzip,  virustotal-python {VERSION}",
    }
    params = {"apikey": API_KEY,"resource":filehash}
    req = urllib.request.Request(f"{BASEURL}file/report?apikey={API_KEY}&resource={filehash}", headers=headers)
    rawresponse = urllib.request.urlopen(req).read()
    resp = json.loads(rawresponse.decode("utf-8"))
    if (resp['response_code'] != 1):
        return dict(
                sha1 = filehash,
                positives = 0,
                total = 0,
                vtlink = f"https://www.virustotal.com/gui/file/{filehash}",
                detect = False,
                error = False
            )
    return dict(
                sha1 = filehash,
                positives = resp['positives'],
                total = resp['total'],
                vtlink = resp['permalink'],
                detect = True if resp['positives'] > 0 else False,
                error = False
            )

# Validate timestamp using hmac
def validatetime(secret,text):
    try:
        key = secret.encode('utf-8')
        data = text.split(".")[0].encode('utf-8')
        t = int(data)
        if( int(time.time()) < t):
            signature = text.split(".")[1].lower()
            sig = hmac.new(key=key, msg=data, digestmod=hashlib.sha256 ).hexdigest().lower()
            if signature == sig :
                return True
    except:
        pass
    return False

#https://www.serverless.com/framework/docs/providers/aws/events/apigateway/#example-lambda-proxy-event-default
def app_handler(event, context):
    global bkt
    global awsregion
    try:
        referer = event["headers"]["Referer"]
    except:
        referer = ""
    path = event["path"]
    # In prod, we will exit and return 200ok
    if (appurl != "devmode" and not referer.startswith(appurl)):
        return {
        "statusCode": 200,
        "body"  : 'ok'
    }
    # If region urlparameter is set, switch target bucket
    if (event["queryStringParameters"] != None and "region" in event["queryStringParameters"]):
        bkt = bktUS
        awsregion = awsregionUS
        if event["queryStringParameters"]["region"] == "au":
            awsregion = awsregionAU
            bkt = bktAU
        elif event["queryStringParameters"]["region"] == "eu":
            awsregion = awsregionEU
            bkt = bktEU
    print("Target bucket is {}".format(bkt))
    split_url = urlsplit(referer)
    clean_path = split_url.scheme+"://"+split_url.netloc

    geturlmatch = re.compile("^/[0-9]+day/[0-9a-fA-F]{64}$")
    deleteurlmatch = re.compile("^/delete/[0-9]+day/[0-9a-fA-F]{64}$")
    headers = {
        'Access-Control-Allow-Origin': clean_path,
        'Content-Type': "application/json"
    }
    statuscode = 404
    body = {"status_code":404}

    if path.startswith('/slack'):
        try:
            body = getshareurl(event)
            statuscode = 200
        except BaseException as err:
            print(traceback.format_exc())
            print(f"Unexpected {err=}, {type(err)=}")
            pass

    elif path.startswith("/gettoken/"):
        expiredurl = True
        if (hmacsecret == "none"):
            expiredurl = False
        elif (event["queryStringParameters"] != None and "exp" in event["queryStringParameters"]):
            signedtimestamp = event["queryStringParameters"]["exp"]
            if (validatetime(hmacsecret,signedtimestamp)):
                expiredurl = False
        # If hmacsecret is not set or the url is not yet expired, generate token.
        if (not expiredurl):
            # /gettoken/{1-5}
            try:
                expiretime=int(path[10:])
                if not ((expiretime in range(1,6) or expiretime == 10)):
                    expiretime = 1
            except:
                expiretime=1

            try:
                body = getposturl(expiretime)
                statuscode = 200
            except:
                pass
        else:
            statuscode = 403
            body = {"err":"Invalid exp value"}

    elif (len(path)==46 and path.startswith("/sha1/")):
        try:
            body = checkvirus(path[6:])
            statuscode = 200
        except:
            pass
    elif(geturlmatch.match(path)):
        try :
            body = getobj(path[1:])
            ## If the file is expired but not yet cleaned up by AWS, we are deleting it and return 404
            if body == None:
                statuscode = 404
                body = {"status_code": 404}
            else:
                statuscode = 200
        except:
            pass

    elif(deleteurlmatch.match(path)):
        body = deleteobj(path[8:])
        statuscode = 200
    return {
        "statusCode": statuscode,
        "headers": headers,
        "body"  : json.dumps(body)
    }
