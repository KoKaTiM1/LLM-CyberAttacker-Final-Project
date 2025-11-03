@echo off
set VM=UbuntuVM_flat
set U=sandbox
set P=1234
set PY=/home/sandbox/venv/bin/python

echo Starting VM headless...
VBoxManage startvm "%VM%" --type headless

rem Wait 60 seconds for VM and Guest Additions to fully load
echo Waiting 60 seconds for VM and Guest Additions to fully initialize...
timeout /t 60 >nul
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
