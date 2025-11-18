@echo off
echo Alternative: Rebasing sandbox branch on top of main...
echo This will replay your changes on top of the latest main branch
echo.

echo WARNING: This will rewrite git history. Make sure you backup your changes first!
echo.
pause

echo 1. Fetching latest changes...
git fetch origin

echo.
echo 2. Rebasing sandbox on top of main...
git rebase origin/main

echo.
echo 3. Current status:
git status

echo.
echo If rebase conflicts occur:
echo 1. Edit conflicted files
echo 2. Run: git add .
echo 3. Run: git rebase --continue
echo 4. Repeat until rebase is complete
echo 5. Run: git push origin sandbox --force-with-lease

pause