#!/opt/homebrew/bin/python3
import requests, json, sys 
import urllib3
import logging


class scops:
    def __init__(self, logindata):
        self.logindata=logindata        
        self.IP=logindata["url"]
        self.scLogin()
        
    def scLogin(self):
        IP=self.logindata["url"]
        username=self.logindata["username"]
        password=self.logindata["password"]
        payload=json.dumps({"username":str(username),"password":str(password),"releaseSession":0})
        headers={"Accept": "application/json, text/javascript"}
        url=str(IP)+"rest/token"
        session = requests.session()
        sonuc=session.post(url=url,data=payload,headers=headers,verify=False)
        self.xsecuritycenter=str(sonuc.json()["response"]["token"])
        self.token="TNS_SESSIONID="+str(requests.utils.dict_from_cookiejar(session.cookies)["TNS_SESSIONID"])
        self.cookie=self.token
        self.headers={"Accept": "application/json, text/javascript","Cookie":str(self.token),"X-SecurityCenter":str(self.xsecuritycenter)}
        
    def getCredentials(self):
        ret=requests.get(url=self.IP+"rest/credential",headers=self.headers,verify=False)  
        out=json.dumps(ret.json(), indent = 3)
        logging.info(out)
    def createPolicy(self,jsoninput):
        payload=json.dumps(jsoninput)
        ret=requests.post(url=self.IP+"rest/policy",data=payload,headers=self.headers,verify=False)  
        out=json.dumps(ret.json(), indent = 3)
        logging.info(out)
    def getIpSummaryOutput(self):
        filter = {
    'query': {
        'description': '',
        'context': '',
        'status': -1,
        'createdTime': 0,
        'modifiedTime': 0,
        'groups': [],
        'type': 'vuln',
        'tool': 'sumip',
        'sourceType': 'cumulative',
        'startOffset': 0,
        'endOffset': 2,
        'filters': [
            {
                'id': 'severity',
                'filterName': 'severity',
                'operator': '=',
                'type': 'vuln',
                'isPredefined': True,
                'value': '4,3,2',
            },
        ],
        'sortColumn': 'score',
        'sortDirection': 'desc',
        'vulnTool': 'sumip',
    },
    'sourceType': 'cumulative',
    'sortField': 'score',
    'sortDir': 'desc',
    'columns': [],
    'type': 'vuln',
}
        ret=requests.post(url=self.IP+"rest/analysis",headers=self.headers, json=filter, verify=False)  
        out=json.dumps(ret.json(), indent = 3)
        iplist=[]
        for ipsummaryresult in ret.json()["response"]["results"]:
            iplist.append(ipsummaryresult["ip"])
        return iplist
    def getIpDetails(self, ip):
        filter = {
    'query': {
        'name': '',
        'description': '',
        'context': '',
        'status': -1,
        'createdTime': 0,
        'modifiedTime': 0,
        'groups': [],
        'type': 'vuln',
        'tool': 'listvuln',
        'sourceType': 'cumulative',
        'startOffset': 0,
        'endOffset': 3,
        'filters': [
            {
                'id': 'ip',
                'filterName': 'ip',
                'operator': '=',
                'type': 'vuln',
                'isPredefined': True,
                'value': ip,
            },
            {
                'id': 'repository',
                'filterName': 'repository',
                'operator': '=',
                'type': 'vuln',
                'isPredefined': True,
                'value': [
                    {
                        'id': '1',
                    },
                ],
            },
            {
                'id': 'severity',
                'filterName': 'severity',
                'operator': '=',
                'type': 'vuln',
                'isPredefined': True,
                'value': '4,3,2',
            },
        ],
        'vulnTool': 'listvuln',
    },
    'sourceType': 'cumulative',
    'columns': [],
    'type': 'vuln',
}
        ret=requests.post(url=self.IP+"rest/analysis",headers=self.headers, json=filter, verify=False)  
        out=json.dumps(ret.json(), indent = 3)
        #logging.warning(ret.json())
        vulnlist=[]
        for vuln in ret.json()["response"]["results"]:
            vulnlist.append(vuln)
        return vulnlist, filter["query"]["filters"]
    def getVulnDetails(self, vuln, myfilter, col):
        protocol = {'ICMP':1,'TCP': 6, 'UDP':17, 'Unknown':0}
        myfilter.append({
                'id': 'pluginID',
                'filterName': 'pluginID',
                'operator': '=',
                'type': 'vuln',
                'isPredefined': True,
                'value': vuln["pluginID"],
            })
        myfilter.append(
            {
                'id': 'port',
                'filterName': 'port',
                'operator': '=',
                'type': 'vuln',
                'isPredefined': True,
                'value': vuln["port"],
            })
        myfilter.append(
            {
                'id': 'protocol',
                'filterName': 'protocol',
                'operator': '=',
                'type': 'vuln',
                'isPredefined': True,
                'value': protocol[vuln["protocol"]],
            })
        filter = {
    'query': {
        'name': '',
        'description': '',
        'context': '',
        'status': -1,
        'createdTime': 0,
        'modifiedTime': 0,
        'groups': [],
        'type': 'vuln',
        'tool': 'vulndetails',
        'sourceType': 'cumulative',
        'startOffset': 0,
        'endOffset': 50,
        'filters': myfilter,
        'vulnTool': 'vulndetails',
    },
    'sourceType': 'cumulative',
    'columns': [],
    'type': 'vuln',
}
        ret=requests.post(url=self.IP+"rest/analysis",headers=self.headers, json=filter, verify=False) 
        try: 
            return ret.json()["response"]["results"][0][col]
        except:
            pass
        return ""

#response = requests.post('https://localhost:8443/rest/analysis', cookies=cookies, headers=headers, json=filter)
