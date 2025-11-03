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

echo whoami:
VBoxManage guestcontrol "%VM%" run --username %U% --password %P% --exe /usr/bin/whoami --

echo ls:
VBoxManage guestcontrol "%VM%" run --username %U% --password %P% --exe /usr/bin/ls -- -la /home/sandbox

echo Python inline:
VBoxManage guestcontrol "%VM%" run --username %U% --password %P% --exe %PY% -- -c "print('connected OK')"

echo print("hello from guestcontrol") > "%TEMP%\guest_test.py"
echo Copying file...
VBoxManage guestcontrol "%VM%" copyto "%TEMP%\guest_test.py" /home/%U%/guest_test.py --username %U% --password %P%

echo Running copied script...
VBoxManage guestcontrol "%VM%" run --username %U% --password %P% --exe %PY% -- /home/%U%/guest_test.py

echo All checks passed ^^^  Shutting down...
VBoxManage controlvm "%VM%" acpipowerbutton
echo Done.
