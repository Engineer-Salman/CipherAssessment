import re

#regex to capture passwords
passwordRegex = re.compile(r"password=([^\s&]+)")

logPath = input("please entire log path: ")

with open(logPath) as logs:
    for line in logs:
        match = passwordRegex.search(line)
        if match:
            print(match.group(1))
        
