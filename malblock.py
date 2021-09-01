import wmi
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
c = wmi.WMI()

sigs = json.loads(requests.get('https://raw.githubusercontent.com/iam-py-test/unwanted-program-removal-tool/main/sha256_sigs.json').text)


newsigs = {}
for cata in sigs:
	for detection in sigs[cata]:
		newsigs[detection] = sigs[cata][detection]

print("Scanning active")
while True:
	for process in c.Win32_Process():
		fpath = process.ExecutablePath
		try:
			sha256f = sha256(open(fpath,"rb").read()).hexdigest()
			for sig in newsigs:
				if sha256f in newsigs[sig]:
					print("File {} detected as {}".format(fpath,sig))
					import subprocess 
					subprocess.run("taskkill /F /IM \"{}\"".format(os.path.split(fpath)[1]))
					os.remove(fpath)
		except Exception as err:
			print(err)
