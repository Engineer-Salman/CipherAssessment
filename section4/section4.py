import requests
import time
import json
from datetime import datetime

apiKey = '22cca6e6979be2ed2639947fb3cca0f5dbfc3dd3f456f69077bd14ee9c69127d'
pathHash = input("enter the path to hashes.txt: ")
vtURL = 'https://www.virustotal.com/api/v3/files/'
outputJson = 'results.json'


HEADERS = {
        'x-apikey': apiKey
        }

def format_timestamp(unix_time):
    try:
        return datetime.utcfromtimestamp(unix_time).strftime('%Y-%m-%d %H:%M:%S')
    except:
        return "Unknown"

def testHash(Hash):
    url = vtURL+ Hash
    response = requests.get(url, headers= HEADERS)
    if response.status_code == 200:
        data = response.json()
        stats = data["data"]["attributes"]
        md5 = stats.get('md5', 'N/A')
        sha1 = stats.get('sha1', 'N/A')
        sha256 = stats.get('sha256', Hash)
        fileType = stats.get('type_description', 'Unknown')
        firstSeen = format_timestamp(stats.get('first_submission_date', 0))
        communityScore = stats.get('reputation', 'N/A')
        
        lastAnalysis = stats.get('last_analysis_stats', {})
        detected = lastAnalysis.get('malicious', 0) + lastAnalysis.get('suspicious', 0)
        total = sum(lastAnalysis.values())

        return {
        "original Hash": Hash,
        "MD5": md5,
        "SHA1": sha1,
        "SHA256": sha256,
        "File Type": fileType,
        "First Seen": firstSeen,
        "Community Score": communityScore,
        "AV Detection": detected
        }

    elif response.status_code == 404:
        print("hash not found on virustotal: "+Hash)
    else:
        print("an error has occured")

resultList = []


with open(pathHash, 'r') as hashFile:
        hashes = [line.strip() for line in hashFile if line.strip()]

        for h in hashes:
            result = testHash(h)
            resultList.append(result)
            time.sleep(15)  # respect rate limit

with open(outputJson, 'w') as jsonFile:
        json.dump(resultList, jsonFile, indent=4)

