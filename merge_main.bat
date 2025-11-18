@echo off
echo Updating sandbox branch with latest changes from main...
echo.

echo 1. Fetching latest changes from remote...
git fetch origin

echo.
echo 2. Checking current branch...
git branch --show-current

echo.
echo 3. Merging main branch into sandbox...
git merge origin/main

echo.
echo 4. Current git status:
git status

echo.
echo If there are merge conflicts, you'll need to:
echo 1. Edit the conflicted files manually
echo 2. Run: git add .
echo 3. Run: git commit -m "Merge main into sandbox"
echo 4. Run: git push origin sandbox

pause