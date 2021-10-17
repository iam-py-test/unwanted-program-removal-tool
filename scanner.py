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
from urllib.parse import urlparse

version = 0.5

try:
	selfhash = sha256(open(__file__,"rb").read()).hexdigest()
except:
	selfhash = ""

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
		try:
			sigs = json.loads(requests.get('https://raw.githubusercontent.com/iam-py-test/unwanted-program-removal-tool/main/sha256_sigs.json').text)
		except:
			print("Failed to load signatures. Please check your internet connection or try again later. \nIf the problem persists, please report it at https://github.com/iam-py-test/unwanted-program-removal-tool/issues")
			input()
			sys.exit()
		try:
			heurrules = json.loads(requests.get("https://raw.githubusercontent.com/iam-py-test/unwanted-program-removal-tool/main/heur.json").text)
		except Exception as err:
			debugerror(err)
	try:
		iam_py_test_list = requests.get("https://raw.githubusercontent.com/iam-py-test/my_filters_001/main/Alternative%20list%20formats/antimalware_domains.txt").text.split("\n")
		ip_block = requests.get("https://raw.githubusercontent.com/iam-py-test/my_filters_001/main/Alternative%20list%20formats/antimalware_ips.txt").text.split("\n")
		dandelion = requests.get("https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareDomains.txt").text.split("\n")
		urlhaus = requests.get("https://curben.gitlab.io/malware-filter/urlhaus-filter-domains.txt").text.split("\n")
		maldomains = iam_py_test_list + ip_block + dandelion + urlhaus
	except Exception as err:
		debugerror(err)
		maldomains = []

def checkheur(root="/",filename=""):
	try:
		ismal = False
		for rule in heurrules:
			ismal = False
			sha256f = sha256(open(os.path.join(root,filename),"rb").read()).hexdigest()
			if sha256f in rule["rule"]["include_sha256s"]:
				ismal = True
				for rulepart in rule["rule"]:
					if rulepart == "exclude_filename_includes":
						for namebit in rule["rule"]["exclude_filename_includes"]:
							if namebit in filename.lower():
								ismal = False
			if ismal == True:
				return "Heuristics:Threat." + rule["detection_name"]
	except Exception as err:
		debugerror(err)
	return False

def checkurlfile(root,filename):
	try:
		text = open(os.path.join(root,filename)).read()
		lines = text.split("\n")
		if "url" in text.lower():
			for line in lines:
				if line.lower().startswith("url="):
					url = line.lower().split("=")
					url.pop(0)
					if len(url) > 1:
						url = url.join("=")
					else:
						url = url[0]
					domain = urlparse(url).netloc
					if domain in maldomains:
						return True
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
if hasarg("--disableallowlist") == False:
	allowlist = ["103a0b9fbd9880194053ec76363aac086e71a56c27b4b696891e42a8424a00d1","56b2d516376328129132b815e22379ae8e7176825f059c9374a33cc844482e64","54d9f98f36bc5511d281318b8022002f74ad30b6383696e861220e15ee68e5a3","6f1c9b4c187669bc0371260d121caf48d65f829a9104c483befbd8fc0bed24f5","886e75c65b77dafbd0d5fd9e99cf7a6dd696a905499b944f3ab53eff667fc635","a83d55c6f3fd0e634d4cd570ced654a8bdc1776027680bc3f003476e764cc499","b5eee9447de44aa5d4303cfc524c88bfc072405a598bb40c57b4db46c93538ca","643ec58e82e0272c97c2a59f6020970d881af19c0ad5029db9c958c13b6558c7","e6f5de8bc3fc572d9a2866024c5af3a83a4d70f4d38810b9e7679a2e9f89775c","a1d7c4e51ab54deb425ad3e425126f66904ab23acec724319eb897ec77fc8f11","e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b","d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35","ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb","1051e9777bf787abf20a473ebff51e7416354624cf6071ad45127b069feb474f","b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9","e387376538f15a27b9548db7abbc04cae62cce7cbe7bacb1b504f5d082ad83fc","24a0e0ace66aeb97d101df232a571368c4068d9b46b9d3e9c22f8c10d0be7dc4","047e2df9ccf0ce298508ee7f0db0abcb2ff9cff9916b6e8a1fbd806b7a9d064b","6780ca70605a2c7a6805cb7b58f7fac8e666ae6c22e266e71761c8722a5030b4","5b97c39d87ad627c53023bfebb0ea1b5227c3f4e86e3bf06b23f3e4b0d6726e2","1043111ff07814b0d3439561b4cee5d7ec1799a7a0a419949fee707666f6dded","b73e0959fe9fb7836b887504f010b15d0de094a9176f3881b1b9922cc469f1e3","26db419399e1df308fc195821858b322146867ca637bc717f3982f8b0dba6db4","e572d9e05fafde8d6baa0c341a3d61a44bfd8c9c71c6080cec7612462666d026","b77aa726acd44c7c89d32dd46aa07583b88fbe2c34aed394eb6e005824e40893","828116872412502ea07dcb46066790f00f7aafcfe1065ecbacafcd5f49d22db1","ba31ad8eca19c5fe03f6a5c64c8e0adfc7bd8d04b1f4e1c11d167467fd5261e9","b139d09d95e5a1de02a00324054fd3db7d7e874e881c2420441f2576496f8695","544fb7cdee7f7ba5eeb2142593a9d031c270ba8962539d19ead0b4cede5aa0b2","031224518c14be0b79149bc9366db44a698e8b6a8985dba19f11dba9ae4dd3ad","6be89bc03c35393dac753068834c89e183e65350cf20013e1907f04563e427de","0ee8e93077a145a586153861fe44dc1b530c95f98c6ef97f8d1c5254a195e243","8767bc230a6928df40b66a1d127c7dbaedf70bd18d5c20c094ffc7f23902a7cf","dfbea9e8c316d9bc118b454b0c722cd674c30d0a256340200e2c3a7480cba674","56afe5133fdc5806ec6b19436f7b55f1499cfc94619740c171424fbcf7808fd3","782260e8ca926830e0de2b8a0248d27fae8aedda701c5e676f84f80ec757d6d0","e7fc40b41aa8b83841a0b96d169eaf0800aa784733e636935374d56536253f10","aff35cc83ff53eca577d6fcdf68f90e5e2f648d33e2fb28b93ae7906cfd1544b","d22f5703a6d3dabe48406ac0c138ef336f04a4ebb4876f61571a0e8210abace1","0322728dbce3a577c4a13b907ad7375d27e74880b63f7371384f67d19197a0ad","56f8cc2c1790c389394733b84c3fb55e10977e9f0fe0c08110ac11f0fe47f05e","be7241a74fe9a9d30e0631e41533a362b21c8f7aae3e5b6ad319cc15c024ec3f","a62be4c8957735e4526fabd46d0ced4780a3328a05599f65358f57a00f985651","2dd456fbae4f1084d59672b13e377fb5c5dac5c0073ed1dbe89b7ecef6ef5a0e","4e305198f15bafd5728b5fb8e7ff48d9f312399c744ecfea0ecac79d93c5e478","35e3f44c587de8bff62095e768c77e12e2c522fb7efd038fffcc0dd2ae960a57","2c6ad3d925c51eed19f2490c24c0be88db5e91fc5ee19c68c3599d319229795f","c8c350fab1130644536db6a84f605791367308b995079ad494d46a8c617c21d6","fc7f45035c95eafdbbb73824765b89936ca702c8a75175a3cb022f9d64b4b423","490a3e109c39ea9410341da55995d4bfcea89f7194a2728d40d4d06c6a7d38bc","b6c0b135bab32c544d0f50f256419a2bbe3fe6b8b2a9559ada630be3e8e81ec1","41f067c3a11b02fe39947f9eba68ae5c7cb5bd1872a6009a4cd1506554a9aba9","08640534773ae55c00c215f1f15209895f44ab4f62ce00d43707443ac2543725","035de0fea440d2e3ad255ee84b388dda538e778877033fdb54b8a61bb0aade56","8ad6f1492e357f57cf42261497ba29122045d4fc0dcc9669aa5ac9b2a4babfa4","c06a18af04680907b2ddb7a87030492b19e5ee4556c90c85b6601033a84b176e","06678bbf954f0bece61062633dc63a52a34a6f3c27ac7108f28c0f0d26bb22a7","82f26a361b0c49bcf7474aa1975530e2711b0d307aad40309e5a2fb02d2a3a01","a7741892bb4f48589e411cedfcc8e62de31e521ef8b97b0467c250cfaabd82da","ff38afb523490e1a9f157c0447bc616b19c22df88bdb45c163243d834e9745f8","32304bd3a2c1deab7d563213d51ac6fc7a9932eb18f6d126aacde99018de1f0e","b0fe0b15bc8a01956e226976c52cceaf306da97371492a0d0cc887588332d7ad","6c4c856d899f208a3c0a31462acf085e51f4ffc9c3d607289ccbb157268ffe56","530d770cc90584a851acd9a4d51dd51e4f5944a1bfc68493fdcc93e10fb05bcc","1dd11682e0a576af522ed694caf953eb0fd6695bda99c6030a8bbbd54920afdc","19cc751b33c3952abd4bd9c318ece4a88e2eef400db6c606940fd615215ac42e","5cf1c31c625c911292a3dcf0b87fc1f23deafa28dc6c71411ca8ec09bbe6357c","0cb141909c4ed4b46bf32e948c6976e1aba62229a7f68e364d81f710b2cdd023","c89d3190a3f02ca6b1b964f7b3061ebc5399f4b7c7bf469ef2c4387bee55dc04","842dd6761d5d3483a3a05b1af5612e6ffc9c7c3bcd13b4437817427bf481f7bc","d90be58b6be24b84b1eb274d31e495ca4da952443ba373bedc5bd2243ef3b5d9","1d4dd818ca32cce058ed41c6fe72decb44537c8503f79cb10ff70d8b23f18366","07ec8faf3854070117a215c30577089abd19deae4660d13b3c0799a0f42813ef","28cdfcceda794e9bd262c5a56519b9cee05d442a80d76c0034f437130b155356","d97f48d26f57487dc6515f263857db150edb51fec830a1a40f200388587fa9a6"]
	allowlist.append(selfhash)
	if hasarg("--debug"):
		print(selfhash)
else:
	allowlist = []

catafordetection = {}

for cata in sigs:
	for detection in sigs[cata]:
		totalsigs += 1
		newsigs[detection] = sigs[cata][detection]
		catafordetection[detection] = cata

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
							cata = catafordetection[sig]
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
								subprocess.Popen("taskkill /F /IM \"{}\"".format(file), stdout=devnull, stderr=devnull)
								os.remove(os.path.join(root,file))
								remed = True
							except Exception as err:
								subprocess.Popen("taskkill /F /IM \"{}\"".format(file), stdout=devnull, stderr=devnull)
								try:
									os.remove(os.path.join(root,file))
								except:
									subprocess.run("taskkill /F /IM \"{}\"".format(file),shell=True)
									os.remove(os.path.join(root,file))
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
				if file.endswith(".url") or file.endswith(".url.txt"):
					result = checkurlfile(root,file)
					if result == True:
						print("Internet shortcut {} in {} leads to a malicious url".format(file,root))
						if hasarg("--autoremove") or hasarg("--autoreact"):
							shouldremove = "y"
						elif hasarg("--reportonly") == True:
							shouldremove = 'n'
						else:
							shouldremove = input("Remove (y/n): ")
						if shouldremove == 'y':
							try:
								os.remove(os.path.join(root,file))
								detectedfiles.append({"path":os.path.join(root,file),"detection":"Internet Shortcut reputation scan: Malicious","rem":True})
							except Exception as err:
								debugerror(err)
								detectedfiles.append({"path":os.path.join(root,file),"detection":"Internet Shortcut reputation scan: Malicious","rem":False})
			except Exception as err:
				print(err)
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
					else:
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
			print("{} was detected as '{}' and removed".format(detection["path"],detection["detection"]))
		else:
			print("{} was detected as '{}', but was not removed".format(detection["path"],detection["detection"]))
input("\nPress enter to end: ")
