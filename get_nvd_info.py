import requests
import sys
import json
import re
import vthread
import pickle
import time

url = "https://services.nvd.nist.gov/rest/json/cve/1.0/"

cve_file = "../../data3.1/data_collection/final_data/all_cve3"
re_cwe = re.compile(r"\"(CWE-\d*?)\"")

# @vthread.pool(8, log=False)
def get_cwe(cve):
    cwe_url = url + cve + "?apiKey=a5883bea-ef55-4d06-9417-a55c31cceeec"
    print(cwe_url)
    # time.sleep(1)
    cwe_response = requests.get(cwe_url)
    if cwe_response.status_code != 200:
        print(cve, cwe_response.status_code)
        return
    cwe_json = json.loads(cwe_response.text)
    cve_id = cwe_json["result"]["CVE_Items"][0]["cve"]["CVE_data_meta"]["ID"]
    cwe = re_cwe.findall(cwe_response.text)
    if cve_id == cve:
        with open("../../data3.1/data_collection/final_data/cve/cwe", "a") as f:
            try:
                print(cve, cwe, file=f)
            except IndexError:
                print(cve, "", file=f)
    else:
        print(cve, "error")


def get_cvss(cve):
    cwe_url = url + cve + "?apiKey=a5883bea-ef55-4d06-9417-a55c31cceeec"
    print(cwe_url)
    cwe_response = requests.get(cwe_url)
    if cwe_response.status_code != 200:
        print(cve, cwe_response.status_code)
        return
    cwe_json = json.loads(cwe_response.text)
    cvss = cwe_json["result"]["CVE_Items"][0]["impact"]["baseMetricV2"]["cvssV2"]["baseScore"]
    # with open("../../data3.1/data_collection/final_data/cvss", "a") as f:
    #     try:
    #         print(cve, cvss, file=f)
    #     except IndexError:
    #         print(cve, "", file=f)

# https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-1010218