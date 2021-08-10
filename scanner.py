import os
import requests
import json
from hashlib import sha256

sigs = json.loads(requests.get('https://raw.githubusercontent.com/iam-py-test/unwanted-program-removal-tool/main/sha256_sigs.json').text)

for root,dirs,files in os.walk("/"):
  for file in files:
    try:
      sha256f = sha256(open(os.path.join(root,file),"wb").read()).hexdigest()
      for cata in sigs:
        for detection in cata:
          if sha256f in sigs[cata][detection]:
            print("{} found found in {}: {}".format(detection,root,file))
            try:
              if input("Remove (y/n): ") == 'y':
                os.remove(os.path.join(root,file))
            except:
              print("Failed to remove file")
    except Exception as err:
      print("Error in scanning file {}: {}".format(file,err))
