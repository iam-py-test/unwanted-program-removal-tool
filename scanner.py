import os
try:
	import requests
except:
	import subprocess
	try:
		if input("Required packages are not installed. Install (y/n)?") == 'y':
			subprocess.run("pip3 install requests",shell=True)
			import requests
	except Exception as err:
		print(err)
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

for root,dirs,files in os.walk(dirtoscan):
	for file in files:
		try:
			sha256f = sha256(open(os.path.join(root,file),"rb").read()).hexdigest()
			for sig in newsigs:
				if sha256f in newsigs[sig]:
					print("File {} in {} has been detected as {}".format(file,root,sig))
					remed = False
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
							remed = True
					except:
						print("Failed to remove file")
					detectedfiles.append({"path":os.path.join(root,file),"detection":sig,"rem":remed})

		except Exception as err:
			print(err)
 
print("\n\n\nDetected malware:\n")
for detection in detectedfiles:
	if detection["rem"] == True:
		print("{} was detected as {} and removed".format(detection["path"],detection["detection"]))
	else:
		print("{} was detected as {}, but was not removed".format(detection["path"],detection["detection"]))
input("Press enter to end: ")
