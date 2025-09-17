# Pyoofer - Advanced Python HWID Spoofer

![Pyoofer Screenshot](https://i.imgur.com/6E1nQPi.png)

Pyoofer is a sophisticated, GUI-based tool for Windows designed to modify a wide range of hardware (HWID) and software identifiers. Built with a modern PyQt6 interface, this tool provides a comprehensive suite of features for users interested in privacy, security research, or educational purposes.

---

##  Warning & Disclaimer

- **This is an advanced tool that modifies critical system files and registry settings.**
- **Use this software entirely at your own risk.** The developer is not responsible for any damage, data loss, system instability, or any other negative consequences that may arise from its use.
- It is **strongly recommended** that you create a **System Restore Point** and **back up all important data** before using this spoofer.
- This tool is intended for **educational and research purposes only**. Using it to bypass software or game restrictions may violate their Terms of Service.

---

##  Features

- **Modern GUI:** An intuitive and clean user interface built with PyQt6 and Qtawesome for icons.
- **Comprehensive Spoofing:** Spoofs Disk Serials, Volume IDs, MAC Addresses, System GUIDs, Windows Product ID, PC Name, and more.
- **Deep Spoofing (External Core):** Utilizes an external C++ executable (`spoofer_core.exe`) to perform a low-level spoof of motherboard and CPU identifiers.
- **System Cleaner:** Removes residual files from popular games, launchers, and anti-cheat systems.
- **Utilities:** Includes tools for Registry Backup/Restore, viewing current system information, and a safe PC restart option.
- **Robust & Safe:** Automatically checks for administrator privileges and required external files on launch. All operations are threaded to keep the UI responsive.

---

##  Requirements

1.  **Operating System:** Windows 10 or Windows 11.
2.  **Permissions:** You **must** run the application as an administrator.
3.  **Python:** Python 3.8 or newer.
4.  **Python Packages:** `PyQt6`, `qtawesome`, `wmi`.
5.  **External Binaries:**
    - `spoofer_core.exe`
    - `VolumeId64.exe`
    - **Note:** These binaries are **included in the repository** for your convenience. If they are missing for any reason, you can download `VolumeId` from the official **[Microsoft Sysinternals Suite](https://learn.microsoft.com/en-us/sysinternals/downloads/volumeid)**. `spoofer_core.exe` must be provided by the user if not found.

---

##  Installation & Setup

#### 1. Clone the Repository
Open a terminal or command prompt and run:
```bash
git clone [https://github.com/snoopzx/Pyoofer.git](https://github.com/snoopzx/Pyoofer.git)
cd Pyoofer
```

#### 2. Install Python Dependencies
You can install the required packages manually or use the provided batch file for a quick setup.

**Easy Method (Recommended):**
- Simply double-click the `install_requirements.bat` file included in the repository.

**Manual Method:**
- Create a file named `requirements.txt` with the content below:
  ```
  PyQt6
  qtawesome
  WMI
  ```
- Run the following command in your terminal:
  ```bash
  pip install -r requirements.txt
  ```

Your project directory should now look like this:
```
Pyoofer/
├── spoofer.py
├── spoofer_core.exe
├── VolumeId64.exe
├── requirements.txt
├── install_requirements.bat   <-- For easy installation
└── run spoofer.bat            <-- For easy launch
```

---

##  How to Use

#### Easy Method (Recommended)
- Simply double-click the **`run spoofer.bat`** file. It will automatically request administrator privileges and launch the application.

#### Manual Method
1.  You must run the script with administrator privileges.
2.  Right-click `spoofer.py` and select "Run as administrator".
3.  **OR**, open a Command Prompt or PowerShell as Administrator, navigate to the project directory, and run:
    ```bash
    python spoofer.py
    ```

#### Recommended Workflow
For the best and safest results, follow these steps in order:

1.  **Backup:** Navigate to the **Utilities** tab and click **Create Registry Backup**.
2.  **Clean (Optional):** Go to the **Cleaners** tab and click **Clean All Traces**.
3.  **Spoof:** Go to the **Spoofers** tab. Click **Spoof All Identifiers** for a full spoof or select individual options.
4.  **Restart:** After spoofing, you **must restart your PC** for all changes to take effect. A pop-up will prompt you to do so.
