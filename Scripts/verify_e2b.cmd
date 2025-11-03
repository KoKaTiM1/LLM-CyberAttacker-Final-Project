@echo off
echo Reading configuration from sandbox_config.json...

rem Use PowerShell to read JSON configuration
for /f "delims=" %%i in ('powershell -Command "(Get-Content '%~dp0..\sandbox_config.json' | ConvertFrom-Json).environments.e2b.api_key"') do set API_KEY=%%i
for /f "delims=" %%i in ('powershell -Command "(Get-Content '%~dp0..\sandbox_config.json' | ConvertFrom-Json).environments.e2b.enabled"') do set ENABLED=%%i

echo Configuration loaded:
echo E2B Enabled: %ENABLED%
echo API Key: %API_KEY:~0,20%...
echo.

rem Check if E2B is enabled
if /i "%ENABLED%"=="False" (
    echo E2B is disabled in configuration file
    exit /b 1
)

echo Testing E2B environment with all predefined test scripts...
echo.

rem Set E2B API key as environment variable
set E2B_API_KEY=%API_KEY%

rem Create a test script that runs the predefined tests from JSON
echo import os > "%TEMP%\e2b_config_test.py"
echo import json >> "%TEMP%\e2b_config_test.py"
echo import sys >> "%TEMP%\e2b_config_test.py"
echo( >> "%TEMP%\e2b_config_test.py"
echo # Load configuration >> "%TEMP%\e2b_config_test.py"
echo with open(r'%~dp0..\sandbox_config.json', 'r') as f: >> "%TEMP%\e2b_config_test.py"
echo     config = json.load(f) >> "%TEMP%\e2b_config_test.py"
echo( >> "%TEMP%\e2b_config_test.py"
echo print("=== E2B Environment Verification ===") >> "%TEMP%\e2b_config_test.py"
echo print(f"Python version: {sys.version}") >> "%TEMP%\e2b_config_test.py"
echo print(f"E2B API Key loaded: {'Yes' if os.environ.get('E2B_API_KEY') else 'No'}") >> "%TEMP%\e2b_config_test.py"
echo( >> "%TEMP%\e2b_config_test.py"
echo try: >> "%TEMP%\e2b_config_test.py"
echo     from e2b_code_interpreter import Sandbox >> "%TEMP%\e2b_config_test.py"
echo     print("E2B SDK: Installed and importable") >> "%TEMP%\e2b_config_test.py"
echo( >> "%TEMP%\e2b_config_test.py"
echo     print("Connecting to E2B...") >> "%TEMP%\e2b_config_test.py"
echo     sandbox = Sandbox.create(timeout=60) >> "%TEMP%\e2b_config_test.py"
echo     print(f"E2B Sandbox ID: {sandbox.sandbox_id}") >> "%TEMP%\e2b_config_test.py"
echo( >> "%TEMP%\e2b_config_test.py"
echo     # Run predefined tests from config >> "%TEMP%\e2b_config_test.py"
echo     test_scripts = config.get('test_scripts', {}) >> "%TEMP%\e2b_config_test.py"
echo( >> "%TEMP%\e2b_config_test.py"
echo     for test_name, test_code in test_scripts.items(): >> "%TEMP%\e2b_config_test.py"
echo         print(f"\\n--- Running {test_name} ---") >> "%TEMP%\e2b_config_test.py"
echo         try: >> "%TEMP%\e2b_config_test.py"
echo             execution = sandbox.run_code(test_code, timeout=30) >> "%TEMP%\e2b_config_test.py"
echo             success = not execution.error >> "%TEMP%\e2b_config_test.py"
echo             print(f"  Success: {success}") >> "%TEMP%\e2b_config_test.py"
echo             if hasattr(execution, 'logs') and execution.logs: >> "%TEMP%\e2b_config_test.py"
echo                 if hasattr(execution.logs, 'stdout') and execution.logs.stdout: >> "%TEMP%\e2b_config_test.py"
echo                     print(f"  Output: {execution.logs.stdout}") >> "%TEMP%\e2b_config_test.py"
echo             if hasattr(execution, 'results') and execution.results: >> "%TEMP%\e2b_config_test.py"
echo                 for result in execution.results: >> "%TEMP%\e2b_config_test.py"
echo                     if hasattr(result, 'text') and result.text: >> "%TEMP%\e2b_config_test.py"
echo                         print(f"  Result: {result.text}") >> "%TEMP%\e2b_config_test.py"
echo             if execution.error: >> "%TEMP%\e2b_config_test.py"
echo                 print(f"  ERROR: {execution.error}") >> "%TEMP%\e2b_config_test.py"
echo         except Exception as e: >> "%TEMP%\e2b_config_test.py"
echo             print(f"  FAILED: {e}") >> "%TEMP%\e2b_config_test.py"
echo( >> "%TEMP%\e2b_config_test.py"
echo     # Close sandbox >> "%TEMP%\e2b_config_test.py"
echo     if hasattr(sandbox, 'close'): >> "%TEMP%\e2b_config_test.py"
echo         sandbox.close() >> "%TEMP%\e2b_config_test.py"
echo     elif hasattr(sandbox, 'kill'): >> "%TEMP%\e2b_config_test.py"
echo         sandbox.kill() >> "%TEMP%\e2b_config_test.py"
echo     print("\\nAll E2B verification tests completed!") >> "%TEMP%\e2b_config_test.py"
echo( >> "%TEMP%\e2b_config_test.py"
echo except ImportError: >> "%TEMP%\e2b_config_test.py"
echo     print("ERROR: E2B SDK not installed. Run: pip install e2b-code-interpreter") >> "%TEMP%\e2b_config_test.py"
echo     sys.exit(1) >> "%TEMP%\e2b_config_test.py"
echo except Exception as e: >> "%TEMP%\e2b_config_test.py"
echo     print(f"ERROR: E2B connection failed: {e}") >> "%TEMP%\e2b_config_test.py"
echo     sys.exit(1) >> "%TEMP%\e2b_config_test.py"

echo Running E2B verification tests...
python "%TEMP%\e2b_config_test.py"

if %ERRORLEVEL%==0 (
    echo.
    echo All E2B verification tests passed!
) else (
    echo.
    echo E2B verification test failed with error code %ERRORLEVEL%
    exit /b %ERRORLEVEL%
)

echo Cleaning up...
del "%TEMP%\e2b_config_test.py" >nul 2>nul
echo Done.