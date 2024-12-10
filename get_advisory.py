import requests
import json
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urlunparse
import os
import re

def get_nvd_advisory(cve_id):
    file_path = f"NVD/{cve_id}.json"
    if os.path.exists(file_path):
        with open(file_path, "r") as file:
            data = json.load(file)
        return data
    f = open("config.json")
    config = json.load(f)
    try:
        # version 2.0
        res = requests.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}", headers={'apiKey':config['nvd_api_key']})
        # version 1.0
        # res = requests.get(f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}?apiKey={config['nvd_api_key']}&addOns=dictionaryCpes")
    except requests.exceptions.RequestException as e:
        # print("Request Error: ", e)
        return None
    data = json.loads(res.text)
    os.makedirs("NVD", exist_ok=True)
    with open(file_path, "w") as file:
        json.dump(data, file, indent=4)
    return data
  
def get_redhat_advisory(cve_id):
    f = open("config.json")
    config = json.load(f)
    api_key = config["redhat_api_key"]
    url = f"https://bugzilla.redhat.com/rest/bug/{cve_id}/comment"
    headers = {
        "Content-Type": "application/json;charset=UTF-8",
        "Authorization": f"Bearer {api_key}"
    }
    
    try:
        response = requests.get(url,headers=headers)
    except requests.exceptions.RequestException as e:
        # print("Request Error: ", e)
        return None
    
    Json = response.json()
    return Json
  
def get_modified_files(commit_url):
    github_regex = re.compile(r"https?://github\.com/([^/]+)/([^/]+)/commit/([a-fA-F0-9]{7,40})")
    match = github_regex.match(commit_url)
    if match:
        owner, repo, commit_sha = match.groups()
        f = open("config.json")
        config = json.load(f)
        api_url = f"https://api.github.com/repos/{owner}/{repo}/commits/{commit_sha}"
        headers = {"Authorization": config["github_api_key"]}
        try:
            response = requests.get(api_url, headers=headers, timeout=10)
        except requests.exceptions.RequestException as e:
            return []
        try:
            commit_data = response.json()
            files = commit_data["files"]
        except (KeyError, TypeError) as e:
            files = []

        modified_files = [file["filename"] for file in files]
        return modified_files
    else:
        return []
  
# print(get_nvd_advisory("CVE-2013-2132"))
# print(get_modified_files("https://github.com/TheAlgorithms/Python/commit/fc33c505935e9927cffb6142591891f721a7bcd9"))