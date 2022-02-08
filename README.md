# Unwanted program removal tool
A tool for removing PUPs using signatures


**WARNING: Due to a bug, the current version flags _ALL_ files as malware. As this may cause harm to your system, please upgrade to the latest version before running this tool**

### What is the unwanted program removal tool?
The unwanted program removal tool is a free and open source tool for removing PUPs, which are often missed by antimalware products
### How do I install it?
The unwanted program removal tool does not require installation; you just need to download and run it.
#### Linux
[Download the ZIP of this repo](https://github.com/iam-py-test/unwanted-program-removal-tool/archive/refs/heads/main.zip) and unzip it.<br>
Open Terminal (or another command line tool) and type `cd ` and then the directory you extracted it to.<br>
Run it using Python. <br>
If you get an error, verify that you have Python 3 installed, and run `pip3 install requests`
#### Windows
[Download the ZIP of this repo](https://github.com/iam-py-test/unwanted-program-removal-tool/archive/refs/heads/main.zip) and unzip it.<br>
Copy the directory where you extracted it to (open it in Explorer and verify  `scanner.py` is in that directory if you are unsure)<br>
Type `cmd` into the Windows search bar. Right click on `Command Prompt` and click `Run as admin` or `Run as administrator`. Confirm in the UAC.<br>
Type `python3 --version`. If you get an error, download and install it from python.org<br>
Type `cd ` and then paste the directory you extracted to, and then type `python3 scanner.py`
