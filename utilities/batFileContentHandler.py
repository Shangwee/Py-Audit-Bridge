def handle_bat_file_content(contentType:str):
    addbat = """@echo off
cls
echo =============================================================
echo Adding Registry Keys...
echo =============================================================

REG ADD HKLM\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters /v SMB1 /t REG_DWORD /d 0 /f
REG ADD HKLM\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters /v AutoShareWks /t REG_DWORD /d 1 /f
REG ADD HKLM\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters /v AutoShareServer /t REG_DWORD /d 1 /f
REG ADD HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f

echo.
echo Registry keys added successfully.
exit /b 0
"""
    deleteBatContent = """@echo off
cls
ECHO =============================================================
ECHO Deleting Registry Keys...
ECHO =============================================================

REG DELETE HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters /v SMB1 /f
REG DELETE HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters /v AutoShareWks /f
REG DELETE HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters /v AutoShareServer /f
REG DELETE HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v LocalAccountTokenFilterPolicy /f

ECHO.
ECHO Registry keys deleted successfully.
exit /b 0
"""

    removeBatContent = """@echo off
cls
ECHO =============================================================
ECHO Reverting Registry Keys...
ECHO =============================================================


REG DELETE HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters /v SMB1 /f
REG DELETE HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters /v AutoShareWks /f
REG DELETE HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters /v AutoShareServer /f
REG DELETE HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v LocalAccountTokenFilterPolicy /f
REG IMPORT C:\\tools\\System.reg
REG IMPORT C:\\tools\\Parameters.reg

ECHO.
ECHO Registry keys reverted successfully.
exit /b 0
"""

    if contentType.lower() == "add":
        return addbat
    elif contentType.lower() == "delete":
        return deleteBatContent
    elif contentType.lower() == "remove":
        return removeBatContent
    else:
        raise ValueError(f"Unknown content type: {contentType}")

    