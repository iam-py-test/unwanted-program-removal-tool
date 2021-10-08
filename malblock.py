import wmi
import os
import subprocess
try:
	import requests
except:
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
allowlist = ["103a0b9fbd9880194053ec76363aac086e71a56c27b4b696891e42a8424a00d1","56b2d516376328129132b815e22379ae8e7176825f059c9374a33cc844482e64","54d9f98f36bc5511d281318b8022002f74ad30b6383696e861220e15ee68e5a3","6f1c9b4c187669bc0371260d121caf48d65f829a9104c483befbd8fc0bed24f5","886e75c65b77dafbd0d5fd9e99cf7a6dd696a905499b944f3ab53eff667fc635","a83d55c6f3fd0e634d4cd570ced654a8bdc1776027680bc3f003476e764cc499","b5eee9447de44aa5d4303cfc524c88bfc072405a598bb40c57b4db46c93538ca","643ec58e82e0272c97c2a59f6020970d881af19c0ad5029db9c958c13b6558c7","e6f5de8bc3fc572d9a2866024c5af3a83a4d70f4d38810b9e7679a2e9f89775c","a1d7c4e51ab54deb425ad3e425126f66904ab23acec724319eb897ec77fc8f11","e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b","d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35","ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb","1051e9777bf787abf20a473ebff51e7416354624cf6071ad45127b069feb474f","b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"]

newsigs = {}
for cata in sigs:
	for detection in sigs[cata]:
		newsigs[detection] = sigs[cata][detection]

print("Scanning active")
while True:
	for process in c.Win32_Process():
		fpath = process.ExecutablePath
		try:
			if fpath == None:
				continue
			sha256f = sha256(open(fpath,"rb").read()).hexdigest()
			if sha256f not in allowlist:
				for sig in newsigs:
					if sha256f in newsigs[sig]:
						print("File {} detected as {}".format(fpath,sig))
						subprocess.run("taskkill /F /IM \"{}\"".format(os.path.split(fpath)[1]))
						try:
							os.remove(fpath)
						except:
							subprocess.run("taskkill /F /IM \"{}\"".format(os.path.split(fpath)[1]))
							os.remove(fpath)
		except Exception as err:
			print(err)
