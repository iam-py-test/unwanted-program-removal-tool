import os
import sys
import subprocess
import time
try:
	import requests
except:
	try:
		devnull = open(os.devnull, 'wb')
		subprocess.Popen("pip3 install requests", stdout=devnull, stderr=devnull)
		time.sleep(1)
		import requests
	except:
		try:
			time.sleep(3)
			import requests
		except Exception as err:
			print(err)
import json
from hashlib import sha256

version = 0.5

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

def debugerror(err,context1="N/A",context2="N/A"):
	if hasarg("--debug"):
		print("UPRT Debug: Error \"{}\" encountered and handled. Additional info: '{}' and '{}' ".format(err,context1,context2))

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

sigs = {"test":{"test":[]}}
heurrules = {}
maldomains = []
def loadsigs():
	global heurrules 
	global sigs
	global maldomains
	if hasarg("--loadsigfile") == True:
		sigfile = input("Enter the name of the sig file: ")
		try:
			sigs = json.loads(open(sigfile).read())
		except:
			print("Error in loading signatures from file. Verify the file exists, and uses valid syntax")
			input("Press enter to end")
			return False
		heurfile = input("Enter the name of the heuristic rules file (leave empty to disable): ")
		if heurfile == "":
			print("Not using heuristics")
			heurrules = {}
		else:
			try:
				heurrules = json.loads(open(heurfile).read())
			except:
				print("Failed to load heur rule file")
				heurrules = {}
		print("\n")
	else:
		sigs = json.loads(requests.get('https://raw.githubusercontent.com/iam-py-test/unwanted-program-removal-tool/main/sha256_sigs.json').text)
		try:
			heurrules = json.loads(requests.get("https://raw.githubusercontent.com/iam-py-test/unwanted-program-removal-tool/main/heur.json").text)
		except Exception as err:
			debugerror(err)
	try:
		maldomains = requests.get("https://raw.githubusercontent.com/iam-py-test/my_filters_001/main/Alternative%20list%20formats/antimalware_domains.txt").text.split("\n")
	except:
		maldomains = []

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

def scanforfake():
	if sys.platform.startswith("win"):
		try:
			print(os.getenv("LOCALAPPDATA"))
			for root,dirs,files in os.walk(os.getenv("LOCALAPPDATA") + "\\Microsoft\\Edge\\User Data\\"):
				for dir in dirs:
					try:
						for root2,dirs2,files2 in os.walk(os.path.join(root,dir)):
							for dir2 in dirs2:
								if dir2.endswith("Platform Notifications"):
									import codecs
									nfile = codecs.open(os.path.join(root2,dir2) + "\\000003.log","r",encoding="utf-8",errors="ignore").read()
									for domain in maldomains:
										if domain in nfile:
											return True
					except Exception as err:
						print("ERR point 2: ",err)
		except Exception as err:
			print(err)
		return False

if hasarg("--nscan") == True:
	resultnote = scanforfake()
	if resultnote == True:
		print("Malware notification setting found")
	else:
		print("No malware notification settings found")

detectedfiles = []
filesscanned = 0

newsigs = {}
totalsigs = 0
totalheurrules = 0
scandone = False

loadsigs()
allowlist = ["103a0b9fbd9880194053ec76363aac086e71a56c27b4b696891e42a8424a00d1","56b2d516376328129132b815e22379ae8e7176825f059c9374a33cc844482e64","54d9f98f36bc5511d281318b8022002f74ad30b6383696e861220e15ee68e5a3","6f1c9b4c187669bc0371260d121caf48d65f829a9104c483befbd8fc0bed24f5","886e75c65b77dafbd0d5fd9e99cf7a6dd696a905499b944f3ab53eff667fc635","a83d55c6f3fd0e634d4cd570ced654a8bdc1776027680bc3f003476e764cc499","b5eee9447de44aa5d4303cfc524c88bfc072405a598bb40c57b4db46c93538ca","643ec58e82e0272c97c2a59f6020970d881af19c0ad5029db9c958c13b6558c7","e6f5de8bc3fc572d9a2866024c5af3a83a4d70f4d38810b9e7679a2e9f89775c","a1d7c4e51ab54deb425ad3e425126f66904ab23acec724319eb897ec77fc8f11","e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b","d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35","ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb","1051e9777bf787abf20a473ebff51e7416354624cf6071ad45127b069feb474f","b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"]

for cata in sigs:
	for detection in sigs[cata]:
		totalsigs += 1
		newsigs[detection] = sigs[cata][detection]

try:
	for rule in heurrules:
		totalheurrules += 1
except Exception as err:
	debugerror(err)

print("------ The Unwanted Program Removal tool ------")
print("Created by iam-py-test")
print("{} total signatures and heuristic rules".format(totalsigs + totalheurrules))
print("Version {}".format(version))
print("-----------------------------------------------\n")
try:
	dirtoscan = input("Enter to dir to scan: ")
except:
	print("\n\n------ Scan terminated ------\n")
	input("Press enter to end: ")
	sys.exit()

start_time = time.time()

try:
	for root,dirs,files in os.walk(dirtoscan):
		for file in files:
			try:
				sha256f = sha256(open(os.path.join(root,file),"rb").read()).hexdigest()
				filesscanned += 1
				if sha256f in allowlist:
					continue
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
									devnull = open(os.devnull, 'wb')
									subprocess.Popen("taskkill /F /IM \"{}\"".format(file), stdout=devnull, stderr=devnull)
								except Exception as err:
									debugerror(err)
								os.remove(os.path.join(root,file))
								remed = True
						except:
							if shouldremove != "y":
								continue
							try:
								devnull = open(os.devnull, 'wb')
								subprocess.Popen("taskkill /F /IM \"{}\"".format(file), stdout=devnull, stderr=devnull)
								time.sleep(5)
								os.remove(os.path.join(root,file))
								remed = True
							except Exception as err:
								print("Failed to remove file: {}".format(err))
						detectedfiles.append({"path":os.path.join(root,file),"detection":sig,"rem":remed})

			except Exception as err:
				debugerror(err)
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
						time.sleep(2)
						os.remove(os.path.join(root,file))
						time.sleep(1)
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
except:
	scandone = False
else:
	scandone = True

if scandone == True:
	print("\n\n\n------ Scan complete -----")
else:
	print("\n\n\n------ Scan ended -----")
scantime = round(time.time() - start_time)
print("Scanned directory {}".format(dirtoscan))
print("{} files scanned".format(filesscanned))
if scantime == 0:
	print("Scan took less than one second")
elif scantime == 1:
	print("Scan took one second")
elif scantime < 60:
	print("Scan took {} seconds".format(scantime))
else:
	try:
		print("Scan took {} minutes".format(round(scantime/60)))
	except:
		print("Scan took {} seconds".format(scantime))
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
