@echo off
echo Reading configuration from sandbox_config.json...

rem Use PowerShell to read JSON configuration
for /f "delims=" %%i in ('powershell -Command "(Get-Content '%~dp0..\sandbox_config.json' | ConvertFrom-Json).environments.virtualbox.vm_name"') do set VM=%%i
for /f "delims=" %%i in ('powershell -Command "(Get-Content '%~dp0..\sandbox_config.json' | ConvertFrom-Json).environments.virtualbox.username"') do set U=%%i
for /f "delims=" %%i in ('powershell -Command "(Get-Content '%~dp0..\sandbox_config.json' | ConvertFrom-Json).environments.virtualbox.password"') do set P=%%i
for /f "delims=" %%i in ('powershell -Command "(Get-Content '%~dp0..\sandbox_config.json' | ConvertFrom-Json).environments.virtualbox.python_path"') do set PY=%%i
for /f "delims=" %%i in ('powershell -Command "$config = (Get-Content '%~dp0..\sandbox_config.json' | ConvertFrom-Json); if ($config.environments.virtualbox.startup_wait_time) { $config.environments.virtualbox.startup_wait_time } else { 60 }"') do set WAIT_TIME=%%i

echo Configuration loaded:
echo VM Name: %VM%
echo Username: %U%
echo Python Path: %PY%
echo Wait Time: %WAIT_TIME% seconds
echo.

echo Starting VM headless...
VBoxManage startvm "%VM%" --type headless

rem Wait for VM and Guest Additions to fully load
echo Waiting %WAIT_TIME% seconds for VM and Guest Additions to fully initialize...
timeout /t %WAIT_TIME% >nul
echo VM should be ready now ^^^

echo Testing VM connectivity...
echo whoami:
VBoxManage guestcontrol "%VM%" run --username %U% --password %P% --exe /usr/bin/whoami --

echo ls:
VBoxManage guestcontrol "%VM%" run --username %U% --password %P% --exe /usr/bin/ls -- -la /home/%U%

echo Python inline test:
VBoxManage guestcontrol "%VM%" run --username %U% --password %P% --exe %PY% -- -c "print('VM Python connection OK')"

echo.
echo Testing VM with all predefined test scripts...
echo.

echo Copying configuration file to VM...
VBoxManage guestcontrol "%VM%" copyto "%~dp0..\sandbox_config.json" /home/%U%/sandbox_config.json --username %U% --password %P%

if not %ERRORLEVEL%==0 (
    echo Failed to copy configuration file to VM
    goto cleanup
)

rem Create a comprehensive test script that reads JSON config from VM
echo import json > "%TEMP%\vm_test.py"
echo import sys >> "%TEMP%\vm_test.py"
echo( >> "%TEMP%\vm_test.py"
echo print("=== VirtualBox Environment Verification ===") >> "%TEMP%\vm_test.py"
echo print(f"Python version: {sys.version}") >> "%TEMP%\vm_test.py"
echo print(f"VM Environment: VirtualBox Guest") >> "%TEMP%\vm_test.py"
echo( >> "%TEMP%\vm_test.py"
echo # Load configuration from VM >> "%TEMP%\vm_test.py"
echo with open('/home/%U%/sandbox_config.json', 'r') as f: >> "%TEMP%\vm_test.py"
echo     config = json.load(f) >> "%TEMP%\vm_test.py"
echo( >> "%TEMP%\vm_test.py"
echo # Run predefined tests from config >> "%TEMP%\vm_test.py"
echo test_scripts = config.get('test_scripts', {}) >> "%TEMP%\vm_test.py"
echo( >> "%TEMP%\vm_test.py"
echo for test_name, test_code in test_scripts.items(): >> "%TEMP%\vm_test.py"
echo     print(f"\\n--- Running {test_name} ---") >> "%TEMP%\vm_test.py"
echo     try: >> "%TEMP%\vm_test.py"
echo         exec(test_code) >> "%TEMP%\vm_test.py"
echo         print(f"  {test_name}: SUCCESS") >> "%TEMP%\vm_test.py"
echo     except Exception as e: >> "%TEMP%\vm_test.py"
echo         print(f"  {test_name}: FAILED - {e}") >> "%TEMP%\vm_test.py"
echo( >> "%TEMP%\vm_test.py"
echo print("\\nAll VM verification tests completed!") >> "%TEMP%\vm_test.py"

echo Copying comprehensive test script to VM...
VBoxManage guestcontrol "%VM%" copyto "%TEMP%\vm_test.py" /home/%U%/vm_test.py --username %U% --password %P%

if %ERRORLEVEL%==0 (
    echo Running comprehensive VM verification tests...
    VBoxManage guestcontrol "%VM%" run --username %U% --password %P% --exe %PY% -- /home/%U%/vm_test.py
    
    if %ERRORLEVEL%==0 (
        echo.
        echo All VM verification tests passed!
    ) else (
        echo.
        echo VM verification test failed with error code %ERRORLEVEL%
    )
) else (
    echo Failed to copy test script to VM
)

:cleanup
echo.
echo Cleaning up and shutting down...
echo Removing test files from VM...
VBoxManage guestcontrol "%VM%" run --username %U% --password %P% --exe /bin/rm -- -f /home/%U%/vm_test.py >nul 2>nul
VBoxManage guestcontrol "%VM%" run --username %U% --password %P% --exe /bin/rm -- -f /home/%U%/sandbox_config.json >nul 2>nul

echo Removing local temporary files...
del "%TEMP%\vm_test.py" >nul 2>nul

echo Shutting down VM...
VBoxManage controlvm "%VM%" acpipowerbutton
echo Done.
