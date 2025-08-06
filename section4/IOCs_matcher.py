import os
import requests
import time
import json
from datetime import datetime

API_KEY = os.getenv('VT_API_KEY')
pathHash = input("enter the path to hashes.txt: ")
vtURL = 'https://www.virustotal.com/api/v3/files/'
outputJson = 'results.json'


HEADERS = {
        'x-apikey': API_KEY
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
