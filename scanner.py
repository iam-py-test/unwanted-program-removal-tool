import os
import sys
from time import sleep
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

version = 1.1

def ZipScan(filename,ffunc):
	import zipfile
	zip = zipfile.ZipFile(filename)
	print(zip)
	for file in zip.namelist():
		ffunc(file,zip.open(file,"r"))

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
						try:
							import subprocess
							subprocess.run("taskkill /F /IM \"{}\"".format(file),shell=True)
							sleep(5)
							os.remove(os.path.join(root,file))
							remed = True
						except Exception  as err:
							print("Failed to remove file: {}".format(err))
					detectedfiles.append({"path":os.path.join(root,file),"detection":sig,"rem":remed})

		except Exception as err:
			print(err)
		try:
			if file.endswith(".zip"):
				def zipf(zf,contents):
					try:
						print(zf)
						sha256f = sha256(contents.read()).hexdigest()
						for sig in newsigs:
							if sha256f in newsigs[sig]:
								print("File {} in {} has been detected as {}".format(zf,root,sig))
								remed = False
								try:
									if input("Remove (y/n): ") == 'y':
										try:
											import subprocess
											subprocess.run("taskkill /F /IM \"{}\"".format(zf),shell=True)
										except:
											pass
										else:
											print("Process {} ended. Removing file...".format(file))
									os.remove(os.path.join(os.path.join(root,file),zf))
									remed = True
								except Exception as err:
									print("Failed to remove file: {}".format(err))
								detectedfiles.append({"path":os.path.join(root,file),"detection":sig,"rem":remed})
					except Exception as err:
						print(err)
				ZipScan(os.path.join(root,file),zipf)
		except Exception as err:
			print(err)
				
 
print("\n\n\nDetected malware:\n")
for detection in detectedfiles:
	if detection["rem"] == True:
		print("{} was detected as {} and removed".format(detection["path"],detection["detection"]))
	else:
		print("{} was detected as {}, but was not removed".format(detection["path"],detection["detection"]))
input("Press enter to end: ")
