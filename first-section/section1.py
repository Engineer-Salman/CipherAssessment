import re

#take the file paths as input
logPath = input("enter the path to the log file")
benignPath = input("enter the path to the benign domains file")

allDomains = []
maliciousEntiries = []
numBenign = 0
logsProcessed = 0

#parses benign domians into a list and compiles it to a regex
with open(benignPath) as benignFile:
    benignDomains = [line.strip() for line in benignFile if line.strip()]

#regex for benign domains
domainRegex = re.compile("|".join(re.escape(domain) for domain in benignDomains))

#note: all malicious domains used tlds other than ".com" but to avoid false positives we will use "randomdomain" as regex
randomDomainRegex = re.compile(r"randomdomain\d+")

#get the number of logs in the file
with open(logPath) as logNum:
    for line in logNum:
        logsProcessed += 1

#open and analyzes the file contents using regex
with open(logPath) as log:
    for line in log:
        fields = line.split()
        domain = fields[10]
        allDomains.append(domain)
        if domainRegex.search(line):
            numBenign += 1
            continue
        if randomDomainRegex.search(line):
            continue
        maliciousEntiries.append(line.split()[10])

#get unique domains only
uniqueDomains = set(allDomains)

print("Total logs processed: "+str(logsProcessed))
print("Unique domains: "+str(len(uniqueDomains)))
print("Benign domains identified: "+str(benignDomains))
print("number of benign domains: "+str(numBenign))
print("suspicious domains identified: "+str(set(maliciousEntiries)))
print("number of suspicious domains: "+str(len(maliciousEntiries)))
