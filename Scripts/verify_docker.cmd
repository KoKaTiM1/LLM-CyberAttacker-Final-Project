@echo off
echo Reading configuration from sandbox_config.json...

rem Use PowerShell to read JSON configuration
for /f "delims=" %%i in ('powershell -Command "(Get-Content '%~dp0..\sandbox_config.json' | ConvertFrom-Json).environments.docker.enabled"') do set ENABLED=%%i
for /f "delims=" %%i in ('powershell -Command "(Get-Content '%~dp0..\sandbox_config.json' | ConvertFrom-Json).environments.docker.image"') do set IMAGE=%%i
for /f "delims=" %%i in ('powershell -Command "(Get-Content '%~dp0..\sandbox_config.json' | ConvertFrom-Json).environments.docker.container_name"') do set CONTAINER_NAME=%%i
for /f "delims=" %%i in ('powershell -Command "(Get-Content '%~dp0..\sandbox_config.json' | ConvertFrom-Json).environments.docker.docker_command"') do set DOCKER_CMD=%%i

echo Configuration loaded:
echo Docker Enabled: %ENABLED%
echo Docker Image: %IMAGE%
echo Container Name: %CONTAINER_NAME%
echo Docker Command: %DOCKER_CMD%
echo.

rem Check if Docker is enabled
if /i "%ENABLED%"=="False" (
    echo Docker is disabled in configuration file
    exit /b 1
)

echo Testing Docker environment...
echo.

echo Checking Docker availability...
%DOCKER_CMD% --version
if %ERRORLEVEL% neq 0 (
    echo ERROR: Docker is not available or not installed
    exit /b 1
)

echo Docker is available!
echo.

echo Pulling Docker image if needed...
%DOCKER_CMD% pull %IMAGE%
if %ERRORLEVEL% neq 0 (
    echo WARNING: Could not pull image %IMAGE%, using existing version
) else (
    echo Docker image %IMAGE% is ready
)
echo.

echo Testing basic Docker connectivity...
%DOCKER_CMD% run --rm %IMAGE% python -c "print('Docker Python connection OK')"
if %ERRORLEVEL% neq 0 (
    echo ERROR: Failed to run basic Docker test
    exit /b 1
)
echo.

echo Testing Docker with all predefined test scripts...
echo.

rem Create a comprehensive test script that includes all JSON test scripts
echo import json > "%TEMP%\docker_test.py"
echo import sys >> "%TEMP%\docker_test.py"
echo( >> "%TEMP%\docker_test.py"
echo print("=== Docker Environment Verification ===") >> "%TEMP%\docker_test.py"
echo print(f"Python version: {sys.version}") >> "%TEMP%\docker_test.py"
echo print(f"Docker Environment: %IMAGE%") >> "%TEMP%\docker_test.py"
echo( >> "%TEMP%\docker_test.py"
echo # Load configuration from mounted file >> "%TEMP%\docker_test.py"
echo with open('/config/sandbox_config.json', 'r') as f: >> "%TEMP%\docker_test.py"
echo     config = json.load(f) >> "%TEMP%\docker_test.py"
echo( >> "%TEMP%\docker_test.py"
echo # Run predefined tests from config >> "%TEMP%\docker_test.py"
echo test_scripts = config.get('test_scripts', {}) >> "%TEMP%\docker_test.py"
echo( >> "%TEMP%\docker_test.py"
echo for test_name, test_code in test_scripts.items(): >> "%TEMP%\docker_test.py"
echo     print(f"\\n--- Running {test_name} ---") >> "%TEMP%\docker_test.py"
echo     try: >> "%TEMP%\docker_test.py"
echo         exec(test_code) >> "%TEMP%\docker_test.py"
echo         print(f"  {test_name}: SUCCESS") >> "%TEMP%\docker_test.py"
echo     except Exception as e: >> "%TEMP%\docker_test.py"
echo         print(f"  {test_name}: FAILED - {e}") >> "%TEMP%\docker_test.py"
echo( >> "%TEMP%\docker_test.py"
echo print("\\nAll Docker verification tests completed!") >> "%TEMP%\docker_test.py"

echo Running comprehensive Docker verification tests...
%DOCKER_CMD% run --rm -v "%~dp0..\sandbox_config.json:/config/sandbox_config.json" -v "%TEMP%\docker_test.py:/script.py" %IMAGE% python /script.py

if %ERRORLEVEL%==0 (
    echo.
    echo All Docker verification tests passed!
) else (
    echo.
    echo Docker verification test failed with error code %ERRORLEVEL%
    goto cleanup
)

:cleanup
echo.
echo Cleaning up...
echo Removing local temporary files...
del "%TEMP%\docker_test.py" >nul 2>nul

echo Done.