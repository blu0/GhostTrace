# 👻 GhostTrace

**GhostTrace** is a cross-platform desktop application for managing detection rules and threat hunting queries across multiple security platforms. Built with Python and Tkinter, it provides a unified interface for storing, editing, searching, and organizing detection logic used in security operations.

> _“Every threat leaves a trace — if you know where to look.”_

📦 [Download GhostTrace v1.0 ZIP](https://github.com/yourusername/yourrepo/releases/latest)

---

## 🧠 Features

- 💾 **Local Detection Rule Library** (JSON-backed)
- 🔍 **Search & Filter** by platform, tags, keywords, or fields
- 🛠️ **Add/Edit Detection Rules** with support for:
  - Title
  - Description
  - Platform (e.g., Sentinel, Splunk, CrowdStrike, Sigma, YARA, Chronicle)
  - Query/logic
  - Tags & References
- 📁 **Import / Export** detection rules from/to JSON files
- ☁️ **Backup & Restore** full libraries
- 🔁 **Conflict Resolution Dialog** for imports
- 🧾 **Formatted Rule Display** with editable fields
- 🖼️ **Custom branding with logo and UI polish**

---

## 💻 Platforms Supported

- Microsoft Sentinel  
- Splunk  
- CrowdStrike  
- YARA  
- Sigma  
- Chronicle (YARA-L)

Platform options are editable in code (see `PLATFORMS = [...]`)

---

## 🚀 Getting Started
### 🔧 Requirements

- **Python 3.7+**
- **Pillow** (for logo image support)

### 🔧 Install Dependencies
```bash
pip install Pillow
```

### 🚀 Run the App
```bash
python ghosttrace.py
```

#### 🪟 To run in the background (Windows only):
1. Right-click `ghosttrace.py`, select **Send to > Desktop (create shortcut)**
2. Right-click the shortcut → **Properties**
3. In the **Target** field, prepend:
   ```
   pythonw.exe
   ```
   **Example:**
   ```
   pythonw.exe "C:\Path\To\ghosttrace.py"
   ```

> Ensure Python is installed and available in your system PATH.

### 🧪 Demo Content
The project includes sample rule libraries and backup files for demonstration and testing.  
Feel free to delete these if starting from scratch.

### 📜 License
GhostTrace is free to use and distribute.  
You may not remove attribution, rename, or rebrand this software without permission.  
All original source and credits must remain intact in any fork or redistribution.

### 🛡️ Built For
Detection engineers, threat hunters, SOC analysts, and purple teamers  
who need a fast, portable way to track and evolve detection content.

🛠️ Built with discipline. Refined with vibe.
