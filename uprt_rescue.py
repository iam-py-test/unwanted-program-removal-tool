import os
import sys
from time import sleep
try:
	import requests
except:
	import subprocess
	try:
		subprocess.run("pip3 install requests",shell=True)
		sleep(2)
		import requests
	except:
		try:
			import requests
		except Exception as err:
			pass
import json
from hashlib import sha256

version = 1.1

if sys.platform.startswith("win"):
	try:
		import ctypes
		def is_admin():
			try:
				return ctypes.windll.shell32.IsUserAnAdmin()
			except:
				return False

		if is_admin():
			pass
		else:
			# Re-run the program with admin rights
			ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
			sys.exit()
	except Exception as err:
		print(err)

dirtoscan = "/"

sigs = json.loads(requests.get('https://raw.githubusercontent.com/iam-py-test/unwanted-program-removal-tool/main/sha256_sigs.json').text)
detectedfiles = []
log = "---- BEGIN UPRT RESCUE LOG ----\n"

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
					try:
						try:
							import subprocess
							subprocess.run("taskkill /F /IM \"{}\"".format(file),shell=True)
						except:
							pass
						else:
							os.remove(os.path.join(root,file))
							remed = True
							log += "Removed file {} in dir {}. File was detected as {}\n".format(file,root,sig)
					except:
						try:
							import subprocess
							subprocess.run("taskkill /F /IM \"{}\"".format(file),shell=True)
							sleep(5)
							os.remove(os.path.join(root,file))
							log += "Removed file {} in dir {}. File was detected as {}\n".format(file,root,sig)
						except Exception  as err:
							log += "Removal failed for file {} in dir {}. File was detected as {}\n".format(file,root,sig)
		except:
			pass
with open("uprt_rescue_log.txt","w") as f:
	f.write(log)
	f.close()
		