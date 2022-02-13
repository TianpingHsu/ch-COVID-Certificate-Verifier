import urllib
import urllib.request
import json
import sys

#https://www.cc.bit.admin.ch/trust/v2/keys/list
#https://www.cc.bit.admin.ch/trust/v2/keys/updates
#https://www.cc.bit.admin.ch/trust/v2/revocationList
#https://www.cc.bit.admin.ch/trust/v2/verificationRules

#baseurl = 'https://www.cc.bit.admin.ch/trust'
#baseurl = 'https://www.cc-a.bit.admin.ch/trust'
baseurl = 'https://www.cc-d.bit.admin.ch/trust'
API_TOKEN = '803f2f37-8e30-43c1-9a09-faa8110ae85'
#API_TOKEN = 'c838a4c4-39e5-4bbb-8e75-e4382df2edfe'

def get_resources(endpoint):
    url         = baseurl + endpoint
    headers     = { "Content-Type":"application/json;charset=utf-8", "Authorization": 'Bearer ' +  API_TOKEN}
    req         = urllib.request.Request(url, headers=headers)
    response    = urllib.request.urlopen(req)
    return response

def get_trustlist():
    try:
        res = get_resources('/v2/keys/updates').read().decode('utf-8')
        print(json.dumps(json.loads(res), indent=4, sort_keys=True), '\n')
    except:
        print('failed to get trust list')


def get_active_kids():
    res = get_resources('/v2/keys/list').read().decode('utf-8')
    print(json.dumps(json.loads(res), indent=4, sort_keys=True), '\n')


def get_revocation_list():
    res = get_resources('/v2/revocationList').read().decode('utf-8')
    print(json.dumps(json.loads(res), indent=4, sort_keys=True), '\n')

def get_verification_rules():
    res = get_resources('/v2/verificationRules').read().decode('utf-8')
    print(json.dumps(json.loads(res), indent=4, sort_keys=True), '\n')

if __name__ == '__main__':
    get_active_kids();
    get_trustlist();
    get_revocation_list()
    get_verification_rules()

