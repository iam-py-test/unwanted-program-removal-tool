import os
import requests
import json
from hashlib import sha256

version = 1.0

dirtoscan = input("Enter to dir to scan: ")

sigs = json.loads(requests.get('https://raw.githubusercontent.com/iam-py-test/unwanted-program-removal-tool/main/sha256_sigs.json').text)
detectedfiles = []

newsigs = {}
for cata in sigs:
	for detection in sigs[cata]:
		newsigs[detection] = sigs[cata][detection]
  
with open("sigs_1.txt","w") as f:
	f.write("{}".format(newsigs))
	f.close()

for root,dirs,files in os.walk(dirtoscan):
	for file in files:
		try:
			sha256f = sha256(open(os.path.join(root,file),"rb").read()).hexdigest()
			for sig in newsigs:
				if sha256f in newsigs[sig]:
					print("File {} in {} has been detected as {}".format(file,root,sig))
					detectedfiles.append({"path":os.path.join(root,file),"detection":sig})
					try:
						if input("Remove (y/n): ") == 'y':
							try:
								import subprocess
								subprocess.run("taskkill /F /IM \"{}\"".format(file),shell=True)
							except:
								pass
							else:
								print("Process {} ended. Removing file...".format(file))
							os.remove(os.path.join(root,file))
					except:
						print("Failed to remove file")
		except Exception as err:
			pass
 
print("\n\n\nDetected malware:\n")
for detection in detectedfiles:
  print("{} was detected as {}".format(detection["path"],detection["detection"]))
input("Press enter to end: ")
