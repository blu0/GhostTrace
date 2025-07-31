GhostTrace: Detection Rule Library
This is a lightweight desktop app for managing detection rules across multiple platforms. You can use it to create, edit, search, and export detection logic for tools such as Sentinel, Splunk, CrowdStrike, Chronicle (YARA-L), YARA, and Sigma. The app saves data locally in a JSON file and requires no internet connection to function.

Features
Add and edit rules with metadata (title, description, tags, references)
Store detection queries for multiple platforms
Search by keyword, tag, or platform
Export rules to .txt for reporting or backup
Import rule sets with conflict resolution
Backup and restore capability
Simple interface with persistent local storage

How to Add More Platforms
If you want to support an additional detection platform (e.g., Elastic, Zeek, Suricata), follow these steps:
Open the script file (e.g., GhostTrace.py) in a text editor.
Find this line near the top of the code:
PLATFORMS = ["Sentinel", "Splunk", "CrowdStrike", "Chronicle (YARA-L)", "YARA", "Sigma"]
Add your custom platform name to the list, preserving quotes and commas. For example:
PLATFORMS = ["Sentinel", "Splunk", "CrowdStrike", "Chronicle (YARA-L)", "YARA", "Sigma", "Elastic"]
Save the file and relaunch the app.

Creating a Desktop Shortcut
You can run the app without showing a terminal window by setting up a shortcut using pythonw.exe.
Steps:
Right-click the Python script file (e.g., GhostTrace.py)
Choose Send to > Desktop (create shortcut)
On the desktop, right-click the new shortcut and choose Properties
In the Target field, prepend the following before the script path: pythonw.exe 
For example:
pythonw.exe "C:\Users\YourName\Documents\GhostTrace.py"
Click OK to save changes. Double-clicking the shortcut will now run the app in the background without opening a console window.

Requirements
Python must be installed on your system.
pythonw.exe must be in your system PATH variable.
(Typically found in the same directory as python.exe, such as C:\Python310\)

You can verify this by typing python --version in a terminal. If it doesn’t work, add Python to your PATH or reinstall Python and select "Add to PATH" during setup.

Demo Files
This app includes demo copies of:
detection_rules.json (example rules)
/backups folder (example backup)
These are safe to delete or replace as needed.