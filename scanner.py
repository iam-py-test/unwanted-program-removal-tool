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
			print(err)
import json
from hashlib import sha256

version = 0.3

def ZipScan(filename,ffunc):
	import zipfile
	zip = zipfile.ZipFile(filename)
	print(zip)
	for file in zip.namelist():
		ffunc(file,zip.open(file,"r"))

def getarg(pos=1):
	try:
		return sys.argv[pos]
	except:
		return None

def hasarg(arg):
	try:
		return arg in sys.argv
	except:
		return False

def debugerror(err):
	if hasarg("--debug"):
		print("UPRT Debug: Error {} encountered and handled".format(err))

if hasarg("--debug"):
	print("UPRT Debug: Running in Debug Mode")
if sys.platform.startswith("win") and hasarg("-noadmin") == False:
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
		debugerror(err)

sigs = json.loads(requests.get('https://raw.githubusercontent.com/iam-py-test/unwanted-program-removal-tool/main/sha256_sigs.json').text)
try:
	heurrules = json.loads(requests.get("https://raw.githubusercontent.com/iam-py-test/unwanted-program-removal-tool/main/heur.json").text)
except Exception as err:
	debugerror(err)

def checkheur(root="/",filename=""):
	try:
		ismal = False
		for rule in heurrules:
			ismal = False
			sha256f = sha256(open(os.path.join(root,filename),"rb").read()).hexdigest()
			if sha256f in rule["rule"]["include_sha256s"]:
				ismal = True
				for namebit in rule["rule"]["exclude_filename_includes"]:
					if namebit in filename.lower():
						ismal = False
			if ismal == True:
				return "Heuristics:Threat." + rule["detection_name"]
	except Exception as err:
		debugerror(err)
	return False

detectedfiles = []

newsigs = {}
totalsigs = 0
totalheurrules = 0
for cata in sigs:
	for detection in sigs[cata]:
		totalsigs += 1
		newsigs[detection] = sigs[cata][detection]

try:
	for rule in heurrules:
		totalheurrules += 1
except:
	pass

print("------ The Unwanted Program Removal tool ------")
print("Created by iam-py-test")
print("{} total signatures and heuristic rules".format(totalsigs + totalheurrules))
print("Version {}".format(version))
print("------------------------------------------------\n")
dirtoscan = input("Enter to dir to scan: ")

for root,dirs,files in os.walk(dirtoscan):
	for file in files:
		try:
			sha256f = sha256(open(os.path.join(root,file),"rb").read()).hexdigest()
			for sig in newsigs:
				if sha256f in newsigs[sig]:
					if hasarg("--autoreact") == False:
						print("File {} in {} has been detected as {}".format(file,root,sig))
					remed = False
					if hasarg("--autoremove") or hasarg("--autoreact"):
						shouldremove = "y"
					elif hasarg("--reportonly") == True:
						shouldremove = 'n'
					else:
						shouldremove = input("Remove (y/n): ")
					try:
						if shouldremove == "y":
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
				import zipfile
				zip = zipfile.ZipFile(os.path.join(root,file))
				hasmalware = False
				try:
					for zfile in zip.namelist():
						try:
							sha256f = sha256(zip.open(zfile,"r").read()).hexdigest()
							for sig in newsigs:
								if sha256f in newsigs[sig]:
									hasmalware = True
						except Exception as err:
							debugerror(err)
				except Exception as err:
					debugerror(err)
				zip.close()
				if hasmalware == True and hasarg("--reportonly") == True:
					print("Zip file {} in {} has malware files in it".format(file,root))
				if hasmalware == True and hasarg("--reportonly") == False:
					shoulddisinfect = input("Zip file {} in {} has malware files in it. Remove malware files? (y/n)".format(file,root))
					zin = zipfile.ZipFile (os.path.join(root,file), 'r')
					zout = zipfile.ZipFile (os.path.join(root,file) + ".TMPX", 'w')
					for item in zin.infolist():
						try:
							buffer = zin.read(item.filename)
							sha256f = sha256(buffer).hexdigest()
							filemal = False
							for sig in newsigs:
								if sha256f in newsigs[sig]:
									filemal = True
							if filemal == False:
								zout.writestr(item, buffer)
						except:
							pass
					zout.close()
					zin.close()
					sleep(2)
					os.remove(os.path.join(root,file))
					sleep(1)
					os.rename(os.path.join(root,file) + ".TMPX",os.path.join(root,file))
					detectedfiles.append({"path":root,"file":file,"detection":sig,"rem":True,"iszip":True})
		except Exception as err:
			debugerror(err)
		try:
			name = checkheur(root,file)
			if name != False:
				print("File {} in {} is detected as {}".format(file,root,name))
				if hasarg("--autoremove") or hasarg("--autoreact"):
					shouldremove = "y"
				elif hasarg("--reportonly") == True:
					shouldremove = 'n'
				else:
					shouldremove = input("Remove (y/n): ")
				if shouldremove == "y":
					try:
						devnull = open(os.devnull, 'wb')
						subprocess.Popen("taskkill /F /IM \"{}\"".format(file), stdout=devnull, stderr=devnull)
					except:
						pass
					try:
						os.remove(os.path.join(root,file))
						detectedfiles.append({"path":os.path.join(root,file),"detection":name,"rem":True})
					except:
						print("Failed to remove threat")
						detectedfiles.append({"path":os.path.join(root,file),"detection":name,"rem":False})
		except:
			pass
				

print("\n\n\n------ Scan complete -----")
print("Scanned directory {}".format(dirtoscan))
print("{} threat(s) detected".format(len(detectedfiles)))
if len(detectedfiles) > 0:
	print("Detected threats:\n")
	for detection in detectedfiles:
		try:
			if detection["iszip"] == True and detection["rem"] == True:
				print("Zip {} in {} contained malware and was disinfected".format(detection["file"],detection["path"]))
				continue
		except:
			pass
		if detection["rem"] == True:
			print("{} was detected as {} and removed".format(detection["path"],detection["detection"]))
		else:
			print("{} was detected as {}, but was not removed".format(detection["path"],detection["detection"]))
input("\nPress enter to end: ")
