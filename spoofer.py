import os
import random
import string
import subprocess
import ctypes
import winreg
import platform
import wmi
import sys
import time
import uuid
from datetime import datetime
import shutil

from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QPushButton, QTextEdit, QLabel,
                             QMessageBox, QGridLayout, QStackedWidget, QFrame, QInputDialog)
from PyQt6.QtCore import (Qt, QThread, QObject, pyqtSignal, pyqtSlot, QSize, QTimer)
from PyQt6.QtGui import (QIcon, QFont)
import qtawesome as qta



BACKUP_CREATED = False

HW_PROFILES = {
    "disks": {
        "samsung": {"length": 15, "chars": string.ascii_uppercase + string.digits, "prefix": "S"}, "western digital": {"length": 12, "chars": string.ascii_uppercase + string.digits, "prefix": "WD-"},
        "seagate": {"length": 8, "chars": string.ascii_uppercase + string.digits, "prefix": "Z"}, "crucial": {"length": 12, "chars": string.digits, "prefix": ""},
        "kingston": {"length": 16, "chars": string.ascii_uppercase + string.digits, "prefix": ""}, "toshiba": {"length": 9, "chars": string.ascii_uppercase + string.digits, "prefix": "Y"},
        "sk hynix": {"length": 20, "chars": string.ascii_uppercase + string.digits, "prefix": ""}, "micron": {"length": 12, "chars": string.digits, "prefix": ""},
        "intel": {"length": 18, "chars": string.ascii_uppercase + string.digits, "prefix": "BT"}, "sandisk": {"length": 10, "chars": string.digits, "prefix": ""},
        "adata": {"length": 15, "chars": string.ascii_uppercase + string.digits, "prefix": "AD"}, "sabrent": {"length": 16, "chars": string.ascii_uppercase + string.digits, "prefix": ""},
        "corsair": {"length": 16, "chars": string.digits, "prefix": ""}, "pny": {"length": 14, "chars": string.ascii_uppercase + string.digits, "prefix": "PN"},
        "vmware": {"length": 4, "chars": string.digits, "prefix": "VMWare_NVME_"}, "vbox": {"length": 17, "chars": string.hexdigits.upper(), "prefix": "VB"},
        "default": {"length": 14, "chars": string.ascii_uppercase + string.digits, "prefix": ""}
    },
    "motherboards": {
        "asus": {"length": 15, "chars": string.ascii_uppercase + string.digits, "prefix": "M"}, "gigabyte": {"length": 12, "chars": string.ascii_uppercase + string.digits, "prefix": "SN"},
        "msi": {"length": 14, "chars": string.ascii_uppercase + string.digits, "prefix": ""}, "asrock": {"length": 10, "chars": string.ascii_uppercase + string.digits, "prefix": "M80-"},
        "evga": {"length": 10, "chars": string.ascii_uppercase + string.digits, "prefix": ""}, "biostar": {"length": 9, "chars": string.ascii_uppercase + string.digits, "prefix": "B"},
        "dell": {"length": 7, "chars": string.ascii_uppercase + string.digits, "prefix": ""}, "hp": {"length": 10, "chars": string.ascii_uppercase + string.digits, "prefix": ""},
        "lenovo": {"length": 8, "chars": string.ascii_uppercase + string.digits, "prefix": "M"}, "supermicro": {"length": 12, "chars": string.ascii_uppercase + string.digits, "prefix": "SM"},
        "vmware": {"length": 22, "chars": string.ascii_uppercase + string.digits, "prefix": "VMW-"}, "virtualbox": {"length": 1, "chars": "", "prefix": "0"},
        "default": {"length": 15, "chars": string.ascii_uppercase + string.digits, "prefix": ""}
    }
}
class Worker(QObject):
    progress = pyqtSignal(str)
    finished = pyqtSignal()
    finished_with_name = pyqtSignal(str)

    def __init__(self, function, task_name, *args, **kwargs):
        super().__init__()
        self.function = function
        self.task_name = task_name
        self.args = args
        self.kwargs = kwargs

    @pyqtSlot()
    def run(self):
        try:
            log_message(f"--- Running task: {self.function.__name__} ---")
            self.kwargs['progress_signal'] = self.progress
            self.function(*self.args, **self.kwargs)
        except Exception as e:
            error_msg = f"[!!!] A critical error occurred in task '{self.function.__name__}': {e}"
            self.progress.emit(error_msg)
            log_message(error_msg)
        finally:
            self.finished.emit()
            self.finished_with_name.emit(self.task_name)

def log_message(message):
    with open("SNO_Spoofer_Log.txt", "a", encoding='utf-8') as f:
        f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {message}\n")
def is_admin():
    try: return ctypes.windll.shell32.IsUserAnAdmin()
    except: return False
def generate_smart_serial(profile_type, vendor_name):
    vendor_key = vendor_name.lower()
    profile = next((value for key, value in HW_PROFILES[profile_type].items() if key in vendor_key), HW_PROFILES[profile_type]["default"])
    serial_len = max(0, profile["length"] - len(profile["prefix"]))
    chars = profile["chars"] or (string.ascii_uppercase + string.digits)
    random_part = ''.join(random.choices(chars, k=serial_len))
    return f"{profile['prefix']}{random_part}"
def create_registry_backup(log_function):
    global BACKUP_CREATED
    if BACKUP_CREATED:
        log_function("[*] Backup for this session already exists.")
        return
    log_function("[*] Creating registry backup...")
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        backup_filename = f"SNO_RegistryBackup_{timestamp}.reg"
        key_to_backup = "HKEY_LOCAL_MACHINE\\SYSTEM"
        command = f'reg export "{key_to_backup}" "{backup_filename}" /y'
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            log_function(f"[+] Backup successful: {backup_filename}")
            log_message(f"Successfully created backup: {backup_filename}")
            BACKUP_CREATED = True
        else:
            log_function(f"[!] Backup failed. Error: {result.stderr}")
    except Exception as e:
        log_function(f"[!] Exception during backup: {e}")

def find_registry_backups(log_function):
    log_function("[*] Searching for registry backups...")
    try:
        script_dir = os.getcwd()
        backup_files = [f for f in os.listdir(script_dir) if f.startswith("SNO_RegistryBackup_") and f.endswith(".reg")]

        if not backup_files:
            log_function("[!] No backup files found.")
            return []

        sorted_backups = sorted(backup_files, key=lambda f: os.path.getctime(os.path.join(script_dir, f)), reverse=True)
        log_function(f"[+] Found {len(sorted_backups)} backup(s).")
        return sorted_backups

    except Exception as e:
        log_function(f"[!] An error occurred while searching for backups: {e}")
        return []

def get_hwid_info_str():
    output = []
    output.append("="*70)
    output.append("                  Comprehensive System Information")
    output.append("="*70)
    output.append(f"\n[+] Basic System & OS Information:")
    output.append(f"    - Computer Name: {platform.node()}")
    output.append(f"    - OS: {platform.system()} {platform.release()} ({platform.machine()})")
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as key:
            output.append(f"    - Product Name: {winreg.QueryValueEx(key, 'ProductName')[0]}")
            output.append(f"    - Product ID: {winreg.QueryValueEx(key, 'ProductId')[0]}")
    except Exception: output.append("    - Product Info: Not found in registry.")
    try:
        c = wmi.WMI()
        output.append("\n[+] Motherboard & BIOS Information:")
        try:
            board = c.Win32_BaseBoard()[0]
            bios = c.Win32_BIOS()[0]
            output.append(f"    - Motherboard Manufacturer: {board.Manufacturer}")
            output.append(f"    - Motherboard Product: {board.Product}")
            output.append(f"    - Motherboard Serial: {board.SerialNumber}")
            output.append(f"    - BIOS Manufacturer: {bios.Manufacturer}")
            output.append(f"    - BIOS Version: {bios.SMBIOSBIOSVersion}")
        except Exception: output.append("    [!] Could not retrieve Motherboard/BIOS information.")
        output.append("\n[+] CPU Information:")
        try:
            processor = c.Win32_Processor()[0]
            output.append(f"    - Name: {processor.Name.strip()}")
            output.append(f"    - Manufacturer: {processor.Manufacturer}")
            output.append(f"    - Processor ID: {processor.ProcessorId}")
        except Exception: output.append("    [!] Could not retrieve CPU information.")
        output.append("\n[+] Graphics Card (GPU) Information:")
        try:
            gpus = c.Win32_VideoController()
            if not gpus: output.append("    - No WMI video controllers found.")
            for gpu in gpus: output.append(f"    - Name: {gpu.Name}")
        except Exception: output.append("    [!] Could not retrieve GPU information.")
        output.append("\n[+] Physical Disk Drive Information:")
        try:
            disks = c.Win32_DiskDrive()
            if not disks: output.append("    - No physical disks found.")
            for disk in disks:
                output.append(f"    - Model: {disk.Model}")
                output.append(f"    - Serial Number: {disk.SerialNumber.strip() if disk.SerialNumber else 'N/A'}")
                output.append("    " + "-" * 50)
        except Exception: output.append("    [!] Could not retrieve physical disk information.")
        output.append("\n[+] Network MAC Addresses:")
        try:
            adapters = c.Win32_NetworkAdapterConfiguration(IPEnabled=True)
            if not adapters: output.append("    - No active network adapters found.")
            for adapter in adapters:
                output.append(f"    - Adapter: {adapter.Description}")
                output.append(f"    - MAC Address: {adapter.MACAddress}")
                output.append("    " + "-" * 50)
        except Exception: output.append("    [!] Could not retrieve MAC addresses.")
        output.append("\n[+] Volume Serial Numbers (Logical Drives):")
        try:
            logical_disks = c.Win32_LogicalDisk()
            if not logical_disks:
                output.append("    - No logical volumes found via WMI.")
            else:
                for disk in logical_disks:
                    serial = disk.VolumeSerialNumber
                    if serial:
                        formatted_serial = "Format Error"
                        try:
                            serial_as_int = int(serial)
                            if serial_as_int < 0:
                                serial_as_int += 2**32
                            serial_hex = hex(serial_as_int)[2:].upper().zfill(8)
                            formatted_serial = f"{serial_hex[:4]}-{serial_hex[4:]}"
                        except ValueError:
                            serial_hex = str(serial).zfill(8)
                            formatted_serial = f"{serial_hex[:4]}-{serial_hex[4:]}"
                        output.append(f"    - Volume ID for {disk.DeviceID}: {formatted_serial}")
                    else:
                        output.append(f"    - Volume ID for {disk.DeviceID}: Not available")
        except Exception as e:
            output.append(f"    [!] Could not retrieve Volume IDs via WMI: {e}")
    except Exception as e:
        output.append(f"\n[!!!] A major WMI error occurred: {e}")
    output.append("\n" + "="*70)
    return "\n".join(output)

def spoof_motherboard_final(progress_signal):
    progress_signal.emit("[*] Calling C++ Core for final motherboard spoof...")
    if not os.path.exists("spoofer_core.exe"):
        progress_signal.emit("[!!!] FATAL ERROR: spoofer_core.exe not found! Cannot perform deep spoof.")
        return
    c = wmi.WMI()
    vendor = c.Win32_BaseBoard()[0].Manufacturer
    new_serial = generate_smart_serial("motherboards", vendor)
    try:
        result = subprocess.run(
            ["spoofer_core.exe", "--motherboard", new_serial],
            capture_output=True, text=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW
        )
        for line in result.stdout.splitlines():
            progress_signal.emit(f"  [C++ Core] {line}")
        progress_signal.emit("[+] C++ Core finished motherboard spoof.")
    except subprocess.CalledProcessError as e:
        progress_signal.emit(f"[!] C++ Core failed for motherboard. Error:\n{e.stderr}")
    except FileNotFoundError:
         progress_signal.emit("[!!!] FATAL ERROR: spoofer_core.exe not found! Make sure it is in the same directory.")

def spoof_cpu_final(progress_signal):
    progress_signal.emit("[*] Calling C++ Core for final CPU spoof...")
    if not os.path.exists("spoofer_core.exe"):
        progress_signal.emit("[!!!] FATAL ERROR: spoofer_core.exe not found! Cannot perform deep spoof.")
        return
    family, model, stepping = "6", random.choice(["94", "142", "158"]), random.randint(3, 13)
    new_identifier = f"Intel64 Family {family} Model {model} Stepping {stepping}"
    try:
        result = subprocess.run(
            ["spoofer_core.exe", "--cpu", new_identifier],
            capture_output=True, text=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW
        )
        for line in result.stdout.splitlines():
            progress_signal.emit(f"  [C++ Core] {line}")
        progress_signal.emit("[+] C++ Core finished CPU spoof.")
    except subprocess.CalledProcessError as e:
        progress_signal.emit(f"[!] C++ Core failed for CPU. Error:\n{e.stderr}")
    except FileNotFoundError:
         progress_signal.emit("[!!!] FATAL ERROR: spoofer_core.exe not found! Make sure it is in the same directory.")
def spoof_disk_serials(progress_signal):
    progress_signal.emit("[*] Smart Spoofing disk serials...")
    try:
        c = wmi.WMI()
        real_disks = {disk.DeviceID: disk.Model for disk in c.Win32_DiskDrive()}
        if not real_disks:
            progress_signal.emit("[!] No disks found via WMI to spoof.")
            return
        base_key_path = r"SYSTEM\CurrentControlSet\Enum\SCSI"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base_key_path) as base_key:
            for i in range(winreg.QueryInfoKey(base_key)[0]):
                disk_class = winreg.EnumKey(base_key, i)
                if 'Disk&Ven' in disk_class:
                    vendor_from_key = disk_class.split('&')[1].replace('Ven_', '').lower()
                    vendor_model = next((model for model in real_disks.values() if vendor_from_key in model.lower()), "default")
                    new_serial = generate_smart_serial("disks", vendor_model)
                    with winreg.OpenKey(base_key, disk_class) as disk_class_key:
                        for j in range(winreg.QueryInfoKey(disk_class_key)[0]):
                            disk_instance = winreg.EnumKey(disk_class_key, j)
                            try:
                                with winreg.OpenKey(disk_class_key, f"{disk_instance}\\Device Parameters", 0, winreg.KEY_SET_VALUE) as dp_key:
                                    winreg.SetValueEx(dp_key, "SerialNumber", 0, winreg.REG_SZ, new_serial)
                                    progress_signal.emit(f"  - Spoofed Disk Serial for: {vendor_model[:20]}...")
                            except FileNotFoundError: continue
        progress_signal.emit("[+] Disk spoofing finished.")
    except Exception as e: progress_signal.emit(f"[!] Disk spoofing failed: {e}")
def spoof_guids(progress_signal):
    progress_signal.emit("[*] Spoofing system GUIDs...")
    try:
        keys_to_spoof = {
            r"SYSTEM\CurrentControlSet\Control\IDConfigDB\Hardware Profiles\0001": "HwProfileGuid",
            r"SOFTWARE\Microsoft\Cryptography": "MachineGuid",
        }
        for path, value_name in keys_to_spoof.items():
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_SET_VALUE) as key:
                    new_guid = str(uuid.uuid4())
                    winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, new_guid)
                    progress_signal.emit(f"  - Spoofed {value_name} successfully.")
            except Exception as e: progress_signal.emit(f"    [!] Failed to spoof {value_name}: {e}")
        progress_signal.emit("[+] GUID spoofing finished.")
    except Exception as e: progress_signal.emit(f"[!] GUID spoofing failed: {e}")
def spoof_product_id(progress_signal):
    progress_signal.emit("[*] Spoofing Windows Product ID...")
    try:
        reg_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path, 0, winreg.KEY_SET_VALUE) as key:
            new_id = '-'.join([''.join(random.choices(string.digits, k=5)) for _ in range(4)])
            winreg.SetValueEx(key, "ProductId", 0, winreg.REG_SZ, new_id)
            progress_signal.emit(f"  - Set ProductId to: {new_id}")
        progress_signal.emit("[+] Product ID spoofing finished.")
    except Exception as e: progress_signal.emit(f"[!] Product ID spoofing failed: {e}")
def spoof_install_date(progress_signal):
    progress_signal.emit("[*] Spoofing Windows install date...")
    try:
        reg_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path, 0, winreg.KEY_SET_VALUE) as key:
            random_seconds = random.randint(30*24*3600, 5 * 365 * 24 * 3600)
            install_timestamp = int(time.time()) - random_seconds
            winreg.SetValueEx(key, "InstallDate", 0, winreg.REG_DWORD, install_timestamp)
            progress_signal.emit(f"  - Set InstallDate to a random past value.")
        progress_signal.emit("[+] Windows install date spoofed.")
    except Exception as e: progress_signal.emit(f"[!] Failed to spoof install date: {e}")
def spoof_user_info(progress_signal):
    progress_signal.emit("[*] Spoofing registered user info...")
    try:
        reg_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path, 0, winreg.KEY_SET_VALUE) as key:
            new_owner = ''.join(random.choices(string.ascii_letters, k=8))
            winreg.SetValueEx(key, "RegisteredOwner", 0, winreg.REG_SZ, new_owner)
            progress_signal.emit(f"  - Set RegisteredOwner to '{new_owner}'.")
        progress_signal.emit("[+] User info spoofed.")
    except Exception as e: progress_signal.emit(f"[!] Failed to spoof user info: {e}")
def change_computer_name(progress_signal):
    progress_signal.emit("[*] Starting advanced computer name change...")
    try:
        new_name = "DESKTOP-" + ''.join(random.choices(string.ascii_uppercase + string.digits, k=7))
        progress_signal.emit(f"  - Setting new name to: {new_name}")
        keys_to_write = {
            r"SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName": "ActiveComputerName",
            r"SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName": "ComputerName",
            r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters": "Hostname"
        }
        for path, value_name in keys_to_write.items():
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_SET_VALUE) as key:
                    winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, new_name)
                log_message(f"Set registry value {value_name} to {new_name}")
            except Exception as e: progress_signal.emit(f"    [!] Could not write to registry key {value_name}: {e}")
        command = f'WMIC computersystem where name="%COMPUTERNAME%" call rename name="{new_name}"'
        result = subprocess.run(command, capture_output=True, text=True, shell=True, timeout=15)
        if result.returncode == 0 and "ReturnValue = 0" in result.stdout:
             progress_signal.emit("[+] WMIC rename command successful.")
        else:
             progress_signal.emit(f"[!] WMIC command failed. Stderr: {result.stderr}")
        progress_signal.emit("[+] Computer name changed. A restart is required.")
    except Exception as e:
        progress_signal.emit(f"[!] A critical error occurred during computer name change: {e}")
def spoof_volume_ids(progress_signal):
    progress_signal.emit("[*] Spoofing Volume IDs...")
    volume_id_exe = "VolumeId64.exe" if os.path.exists("VolumeId64.exe") else "VolumeId.exe"
    if not os.path.exists(volume_id_exe):
        progress_signal.emit("[!] VolumeID.exe / VolumeID64.exe not found. Skipping.")
        log_message("VolumeID tool not found, skipping volume spoof.")
        return
    for letter in "CDEFGHIJKLMNOPQRSTUVWXYZ":
        drive = f"{letter}:"
        if os.path.exists(drive + "\\"):
            new_id = f"{''.join(random.choices('0123456789ABCDEF', k=4))}-{''.join(random.choices('0123456789ABCDEF', k=4))}"
            progress_signal.emit(f"  - Changing Volume ID for {drive} to {new_id}")
            command = [volume_id_exe, drive, new_id]
            try:
                result = subprocess.run(command, capture_output=True, text=True, timeout=15)
                if "Volume ID updated" in result.stdout:
                     progress_signal.emit(f"    [+] Successfully changed Volume ID for {drive}.")
                else:
                     progress_signal.emit(f"    [!] Failed to change Volume ID for {drive}. May be in use.")
            except Exception as e:
                progress_signal.emit(f"    [!] An error occurred for {drive}: {e}")
    progress_signal.emit("[+] Volume ID spoofing finished.")
def spoof_mac_address(progress_signal):
    progress_signal.emit("[*] Spoofing MAC Addresses...")
    try:
        reg_base_path = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_base_path) as base_key:
            for i in range(winreg.QueryInfoKey(base_key)[0]):
                try:
                    adapter_key_name = winreg.EnumKey(base_key, i)
                    with winreg.OpenKey(base_key, adapter_key_name, 0, winreg.KEY_SET_VALUE) as adapter_key:
                        new_mac = "0" + random.choice("26AE") + "".join(random.choices(string.hexdigits.upper(), k=10))
                        winreg.SetValueEx(adapter_key, "NetworkAddress", 0, winreg.REG_SZ, new_mac)
                        progress_signal.emit(f"  - Spoofed MAC for adapter {adapter_key_name} to {new_mac}")
                except OSError:
                    continue
                except Exception as e:
                    progress_signal.emit(f"  [!] Could not spoof MAC for adapter {adapter_key_name}: {e}")
        progress_signal.emit("[+] MAC Address spoofing finished. Restart or network adapter reset required.")
    except Exception as e:
        progress_signal.emit(f"[!] MAC address spoofing failed: {e}")

def clean_all_traces(progress_signal): 
    progress_signal.emit("[*] Starting deep trace cleaning...")
    env_vars = {
        'LOCALAPPDATA': os.environ.get('LOCALAPPDATA', ''), 'APPDATA': os.environ.get('APPDATA', ''),
        'PROGRAMDATA': os.environ.get('PROGRAMDATA', ''), 'USERPROFILE': os.path.expanduser('~'),
        'WINDIR': os.environ.get('WINDIR', 'C:\\Windows')
    }
    paths_to_clean = [
        os.path.join(env_vars['LOCALAPPDATA'], 'Ubisoft Game Launcher'), os.path.join(env_vars['LOCALAPPDATA'], 'Riot Games'),
        os.path.join(env_vars['LOCALAPPDATA'], 'EpicGamesLauncher'), os.path.join(env_vars['LOCALAPPDATA'], 'Electronic Arts'),
        os.path.join(env_vars['LOCALAPPDATA'], 'Origin'), os.path.join(env_vars['APPDATA'], 'Origin'),
        os.path.join(env_vars['PROGRAMDATA'], 'Origin'), os.path.join(env_vars['PROGRAMDATA'], 'Battle.net'),
        os.path.join(env_vars['PROGRAMDATA'], 'Blizzard Entertainment'), os.path.join(env_vars['APPDATA'], 'Battle.net'),
        os.path.join(env_vars['USERPROFILE'], 'Documents', 'Rockstar Games'),
        os.path.join(env_vars['APPDATA'], 'EasyAntiCheat'), os.path.join(env_vars['PROGRAMDATA'], 'EasyAntiCheat'),
        os.path.join(env_vars['WINDIR'], 'System32', 'EasyAntiCheat'),
        os.path.join(env_vars['LOCALAPPDATA'], 'BattlEye'), os.path.join(env_vars['PROGRAMDATA'], 'BattlEye'),
        os.path.join(env_vars['WINDIR'], 'System32', 'drivers', 'BEDaisy.sys'),
        os.path.join(env_vars['WINDIR'], 'System32', 'drivers', 'BEService.exe'),
        os.path.join(env_vars['LOCALAPPDATA'], 'FiveM'), os.path.join(env_vars['LOCALAPPDATA'], 'DigitalEntitlements'),
        os.path.join(env_vars['WINDIR'], 'Prefetch')
    ]
    for path in paths_to_clean:
        if os.path.exists(path):
            try:
                if os.path.isdir(path):
                    shutil.rmtree(path, ignore_errors=True)
                    progress_signal.emit(f"  - Removed directory: {os.path.basename(path)}")
                else:
                    os.remove(path)
                    progress_signal.emit(f"  - Removed file: {os.path.basename(path)}")
            except Exception as e:
                progress_signal.emit(f"  [!] Could not clean {os.path.basename(path)}: {e}")
        else:
            progress_signal.emit(f"  - Trace '{os.path.basename(path)}' not found, skipping.")
    progress_signal.emit("[+] Deep trace cleaning finished.")

class SpooferApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.thread, self.worker = None, None
        self.buttons = {}
        self.initUI()
        self.apply_stylesheet()
        # The dependency check is now called *after* a short delay.
        # This ensures the main window is fully drawn before the pop-up appears.
        QTimer.singleShot(100, self.check_dependencies_and_scan)
        
    def initUI(self):
        self.setWindowTitle("Pyoofr")
        self.setWindowIcon(qta.icon("fa5s.user-secret", color='#00aaff'))
        self.setMinimumSize(1000, 800)
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        nav_bar = QFrame()
        nav_bar.setObjectName("NavBar")
        nav_bar.setFixedWidth(220)
        nav_bar_layout = QVBoxLayout(nav_bar)
        nav_bar_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        nav_bar_layout.setContentsMargins(10, 20, 10, 10)
        nav_bar_layout.setSpacing(15)
        title_label = QLabel("S  N  O")
        title_label.setObjectName("TitleLabel")
        title_label.setFont(QFont("Segoe UI Black", 18))
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        nav_bar_layout.addWidget(title_label)
        nav_bar_layout.addSpacing(20)
        self.stacked_widget = QStackedWidget()
        self.nav_buttons = {}
        nav_items = [("Dashboard", "fa5s.tachometer-alt"), ("Spoofers", "fa5s.user-secret"),
                     ("Cleaners", "fa5s.soap"), ("Utilities", "fa5s.tools")]
        for index, (text, icon) in enumerate(nav_items):
            button = self.create_nav_button(text, icon)
            button.clicked.connect(lambda _, i=index: self.stacked_widget.setCurrentIndex(i))
            nav_bar_layout.addWidget(button)
            self.nav_buttons[text] = button
        self.nav_buttons["Dashboard"].setChecked(True)
        nav_bar_layout.addStretch()
        about_button = self.create_nav_button("About Dev", "fa5s.info-circle")
        about_button.setCheckable(False)
        about_button.setAutoExclusive(False)
        about_button.clicked.connect(self.show_about_dialog)
        nav_bar_layout.addWidget(about_button)
        main_layout.addWidget(nav_bar)
        main_layout.addWidget(self.stacked_widget)
        self.dashboard_page, self.spoofers_page, self.cleaners_page, self.utilities_page = QWidget(), QWidget(), QWidget(), QWidget()
        self.create_dashboard_page()
        self.create_spoofers_page()
        self.create_cleaners_page()
        self.create_utilities_page()
        self.stacked_widget.addWidget(self.dashboard_page)
        self.stacked_widget.addWidget(self.spoofers_page)
        self.stacked_widget.addWidget(self.cleaners_page)
        self.stacked_widget.addWidget(self.utilities_page)
        self.stacked_widget.setCurrentIndex(0)
        
    def create_nav_button(self, text, icon):
        button = QPushButton(f" {text}")
        button.setObjectName("NavButton")
        button.setIcon(qta.icon(icon, color='#e0e0e0'))
        button.setIconSize(QSize(20, 20))
        button.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        button.setCheckable(True)
        button.setAutoExclusive(True)
        return button

    def create_page_layout(self, page):
        layout = QVBoxLayout(page)
        layout.setContentsMargins(25, 20, 25, 20)
        page_title = QLabel("Page Title")
        page_title.setObjectName("PageTitle")
        page_title.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        layout.addWidget(page_title)
        return layout, page_title

    def create_dashboard_page(self):
        layout, title = self.create_page_layout(self.dashboard_page)
        title.setText("System Dashboard")
        self.info_display = QTextEdit()
        self.info_display.setReadOnly(True)
        self.info_display.setFont(QFont("Consolas", 10))
        self.info_display.setPlaceholderText("Scanning system...")
        layout.addWidget(self.info_display)

    def create_spoofers_page(self):
        layout, title = self.create_page_layout(self.spoofers_page)
        title.setText("HWID Spoofer Tools")
        grid_layout = QGridLayout()
        grid_layout.setSpacing(15)
        spoofer_actions = {
            "Spoof Disk Serials": (spoof_disk_serials, "fa5s.hdd", "Changes disk serial numbers in the registry."),
            "Spoof Volume IDs": (spoof_volume_ids, "fa5s.compact-disc", "Changes Volume IDs for C:, D:, etc. (Requires VolumeID.exe)"),
            "Spoof MAC Address": (spoof_mac_address, "fa5s.network-wired", "Changes MAC Address for physical network adapters."),
            "Final Spoof CPU ID (C++)": (spoof_cpu_final, "fa5s.brain", "Calls C++ Core for deep Processor ID spoofing."),
            "Spoof System GUIDs": (spoof_guids, "fa5s.fingerprint", "Changes unique Windows installation IDs."),
            "Final Spoof Motherboard (C++)": (spoof_motherboard_final, "fa5s.microchip", "Calls C++ Core for deep motherboard serial spoofing."),
            "Spoof Product ID": (spoof_product_id, "fa5s.barcode", "Changes the Windows Product ID."),
            "Spoof Install Time": (spoof_install_date, "fa5s.calendar-alt", "Changes the reported Windows installation date."),
            "Spoof PC Name": (change_computer_name, "fa5s.laptop-code", "Changes the computer name."),
        }
        row, col = 0, 0
        for text, (func, icon, tooltip) in spoofer_actions.items():
            button = self.create_action_button(text, icon, lambda _, f=func: self.run_task(f), tooltip)
            grid_layout.addWidget(button, row, col)
            self.buttons[text] = button
            col += 1
            if col > 1: col, row = 0, row + 1
        layout.addLayout(grid_layout)
        layout.addStretch()
        spoof_all_button = self.create_action_button("Spoof All Identifiers", "fa5s.magic", self.run_spoof_all, "Runs all spoofing functions in sequence.")
        spoof_all_button.setObjectName("SpoofAllButton")
        layout.addWidget(spoof_all_button)
        self.buttons["Spoof All"] = spoof_all_button

    def create_cleaners_page(self):
        layout, title = self.create_page_layout(self.cleaners_page)
        title.setText("System & Game Cleaners")
        cleaner_layout = QVBoxLayout()
        cleaner_layout.setSpacing(15)
        clean_all_button = self.create_action_button("Clean All Traces", "fa5s.bomb", lambda: self.run_task(clean_all_traces), "Deep cleans traces for games, launchers, and anti-cheats.")
        clean_all_button.setObjectName("SpoofAllButton")
        cleaner_layout.addWidget(clean_all_button)
        self.buttons["Clean All"] = clean_all_button
        layout.addLayout(cleaner_layout)
        layout.addStretch()

    def create_utilities_page(self):
        layout, title = self.create_page_layout(self.utilities_page)
        title.setText("Utilities & Logs")
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setFont(QFont("Consolas", 9))
        backup_button = self.create_action_button("Create Registry Backup", "fa5s.save", lambda: self.run_task(create_registry_backup), "Creates a backup of critical system registry hives.")
        self.buttons["Create Backup"] = backup_button
        restore_button = self.create_action_button("Restore From Backup", "fa5s.undo", self.run_restore_confirmation, "Restores the registry from a chosen backup file.")
        self.buttons["Restore Backup"] = restore_button
        restart_button = self.create_action_button("Restart PC", "fa5s.power-off", self.run_restart_confirmation, "Restarts the computer after a 10-second countdown.")
        self.buttons["Restart PC"] = restart_button
        util_layout = QGridLayout()
        util_layout.addWidget(backup_button, 0, 0)
        util_layout.addWidget(restore_button, 0, 1)
        util_layout.addWidget(restart_button, 1, 0, 1, 2)
        layout.addLayout(util_layout)
        layout.addWidget(QLabel("Live Activity Log:"))
        layout.addWidget(self.log_output)

    def create_action_button(self, text, icon, func, tooltip=None):
        button = QPushButton(f" {text}")
        button.setObjectName("ActionButton")
        button.setIcon(qta.icon(icon, color='white'))
        button.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        button.setFixedHeight(50)
        button.clicked.connect(func)
        if tooltip: button.setToolTip(tooltip)
        return button

    def apply_stylesheet(self):
        self.setStyleSheet("""
            #NavBar { background-color: #21252b; } #TitleLabel { color: #ffffff; } #PageTitle { color: #ffffff; padding-bottom: 10px; }
            QStackedWidget > QWidget { background-color: #2c313a; } QLabel { color: #d0d0d0; font-size: 18pt; }
            QToolTip { background-color: #21252b; color: #f0f0f0; border: 1px solid #0078d4; }
            #NavButton { text-align: left; padding: 12px; border-radius: 5px; color: #d0d0d0; }
            #NavButton:hover { background-color: #353b45; } #NavButton:checked { background-color: #0078d4; color: white; }
            #ActionButton { background-color: #3a3f4b; border: 1px solid #4a4f5b; color: white; border-radius: 5px; }
            #ActionButton:hover { background-color: #4a4f5b; } #ActionButton:disabled { background-color: #30333a; color: #666; }
            #SpoofAllButton { background-color: #0078d4; color: white; border: none; }
            #SpoofAllButton:hover { background-color: #0088e4; } #SpoofAllButton:disabled { background-color: #005a9e; }
            QTextEdit { background-color: #21252b; border: 1px solid #4a4f5b; border-radius: 5px; padding: 5px; color: #e0e0e0; }
        """)

    def show_about_dialog(self):
        QMessageBox.information(self, "About The Developer", """
            <p><b>Pyoofr</b></p>
            <p>Developed by: <b>SNO</b></p>
            <p><b>Disclaimer:</b> This tool modifies critical system settings. 
            Use it at your own risk. The developer is not responsible for any damage to your system.</p>
            <p>Find more of my work on GitHub:</p>
            <a href='https://github.com/snoopzx'>https://github.com/snoopzx</a>
            """)
    
    def check_dependencies_and_scan(self):
        """Checks for dependencies and then runs the initial HWID scan."""
        self.check_dependencies()
        self.run_show_hwid_info()

    def check_dependencies(self):
        """Checks for external dependencies, disables UI elements, and shows a startup warning if necessary."""
        missing_files = []
        core_missing = not os.path.exists("spoofer_core.exe")
        volid_missing = not (os.path.exists("VolumeId64.exe") or os.path.exists("VolumeId.exe"))
        
        if "Final Spoof CPU ID (C++)" in self.buttons and "Final Spoof Motherboard (C++)" in self.buttons:
            if core_missing:
                self.buttons["Final Spoof CPU ID (C++)"].setEnabled(False)
                self.buttons["Final Spoof Motherboard (C++)"].setEnabled(False)
                self.buttons["Final Spoof CPU ID (C++)"].setToolTip("Required file not found: spoofer_core.exe")
                self.buttons["Final Spoof Motherboard (C++)"].setToolTip("Required file not found: spoofer_core.exe")
                if "spoofer_core.exe" not in missing_files: missing_files.append("spoofer_core.exe")

        if "Spoof Volume IDs" in self.buttons:
            if volid_missing:
                self.buttons["Spoof Volume IDs"].setEnabled(False)
                self.buttons["Spoof Volume IDs"].setToolTip("Required file not found: VolumeId64.exe")
                if "VolumeId64.exe / VolumeId.exe" not in missing_files: missing_files.append("VolumeId64.exe / VolumeId.exe")

        if missing_files:
            log_message = "[!] WARNING: Some required .exe files are missing. Relevant functions have been disabled."
            self.log_output.append(log_message)
            warning_title = "Warning: Missing Required Files"
            warning_text = (
                "The following files were not found:\n\n"
                f"- {', '.join(missing_files)}\n\n"
                "Functions that depend on these files have been disabled.\n"
                "Please place the required files in the same folder as the program."
            )
            QMessageBox.warning(self, warning_title, warning_text)

    def set_buttons_enabled(self, enabled):
        for button in self.buttons.values():
            if button: button.setEnabled(enabled)
        if enabled:
            self.check_dependencies()

    def get_hwid_task(self, progress_signal):
        result_string = get_hwid_info_str()
        progress_signal.emit(result_string)

    def run_show_hwid_info(self):
        self.info_display.setText("Scanning system, please wait...")
        self.run_task(self.get_hwid_task, on_finish_slot=self.update_info_display)

    def run_task(self, function, on_finish_slot=None):
        self.set_buttons_enabled(False)
        if self.stacked_widget.currentIndex() != 3: self.log_output.clear()
        if function.__name__ not in ['get_hwid_task', 'create_registry_backup']:
            create_registry_backup(self.log_output.append)
        self.thread = QThread()
        self.worker = Worker(function, function.__name__)
        self.worker.moveToThread(self.thread)
        self.worker.progress.connect(self.update_log)
        self.thread.started.connect(self.worker.run)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)
        self.thread.finished.connect(lambda: self.set_buttons_enabled(True))
        self.worker.finished_with_name.connect(self.on_task_finished)
        if on_finish_slot: self.worker.progress.connect(on_finish_slot)
        self.thread.start()

    def run_spoof_all(self):
        if QMessageBox.question(self, "Confirm Spoofing", "This will run all recommended spoofing functions.\nA backup will be created.\n\nAre you sure you want to proceed?") == QMessageBox.StandardButton.Yes:
            self.run_task(self.spoof_all_sequence)

    def run_restart_confirmation(self):
        if QMessageBox.question(self, "Confirm Restart", "Are you sure you want to restart your computer?\nAll unsaved work will be lost.") == QMessageBox.StandardButton.Yes:
            self.log_output.append("[+] System will restart in 10 seconds.")
            os.system("shutdown /r /t 10")
    
    def run_restore_confirmation(self):
        self.log_output.clear()
        backup_files = find_registry_backups(self.log_output.append)
        if not backup_files:
            QMessageBox.information(self, "Not Found", "No registry backup files (SNO_RegistryBackup_*.reg) were found.")
            return
        chosen_backup = ""
        if len(backup_files) == 1:
            chosen_backup = backup_files[0]
            self.log_output.append(f"[*] Single backup found: {chosen_backup}")
        else:
            item, ok = QInputDialog.getItem(self, "Select Backup to Restore", 
                                            "Multiple backups found. Please choose one to restore:", backup_files, 0, False)
            if ok and item: chosen_backup = item
        if chosen_backup:
            full_path = os.path.join(os.getcwd(), chosen_backup)
            reply = QMessageBox.question(self, "Confirm Restore", 
                                         f"Are you sure you want to restore the registry from:\n\n{chosen_backup}\n\n"
                                         "This will revert system changes and requires a restart.",
                                         QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, 
                                         QMessageBox.StandardButton.No)
            if reply == QMessageBox.StandardButton.Yes:
                self.log_output.append(f"[*] Restoring from {chosen_backup}...")
                command = f'reg import "{full_path}"'
                try:
                    result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=60, check=True)
                    self.log_output.append(f"[+] Registry restored successfully.")
                    QMessageBox.information(self, "Success", "Registry has been restored. Please restart your PC.")
                except subprocess.CalledProcessError as e:
                    self.log_output.append(f"[!] Restore failed. Error: {e.stderr}")
                    QMessageBox.critical(self, "Error", f"Failed to restore registry.\n\nError: {e.stderr}")

    def spoof_all_sequence(self, progress_signal):
        tasks = [
            spoof_guids, spoof_motherboard_final, spoof_cpu_final, spoof_product_id,
            spoof_install_date, spoof_user_info, change_computer_name,
            spoof_disk_serials, spoof_volume_ids, spoof_mac_address
        ]
        for task in tasks:
            task(progress_signal)
            progress_signal.emit("-" * 40)
            time.sleep(0.5)
        progress_signal.emit("\n[!!!] SPOOFING COMPLETE. A RESTART IS REQUIRED. [!!!]")

    @pyqtSlot(str)
    def on_task_finished(self, task_name):
        if task_name == 'spoof_all_sequence':
            reply = QMessageBox.question(self, 
                                         "Restart Required",
                                         "All spoofing operations are complete. A restart is required to apply all changes.\n\nWould you like to restart now?",
                                         QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                         QMessageBox.StandardButton.Yes)
            if reply == QMessageBox.StandardButton.Yes:
                self.log_output.append("[+] System will restart in 10 seconds.")
                os.system("shutdown /r /t 10")

    @pyqtSlot(str)
    def update_log(self, text):
        self.log_output.append(text)

    @pyqtSlot(str)
    def update_info_display(self, text):
        self.info_display.setText(text)
        self.update_log("[+] System scan complete.")

if __name__ == "__main__":
    if not is_admin():
        app = QApplication(sys.argv)
        QMessageBox.critical(None, "Error", "Administrator Privileges Required.\nPlease run this application as an administrator.")
        sys.exit()

    app = QApplication(sys.argv)
    window = SpooferApp()
    window.show()
    sys.exit(app.exec())