"""
Fix encoding issues in sandbox.py
This script adds encoding='utf-8', errors='replace' to all subprocess.run calls
"""

import re
import sys

def fix_subprocess_encoding(content):
    """Add encoding='utf-8', errors='replace' to subprocess.run calls"""
    
    # Pattern to match subprocess.run with text=True but without encoding
    # This matches the entire subprocess.run call including all parameters
    pattern = r'(subprocess\.run\([^)]*text=True[^)]*?)(\s*\))'
    
    def add_encoding(match):
        call_content = match.group(1)
        closing_paren = match.group(2)
        
        # Check if encoding is already present
        if 'encoding=' in call_content:
            return match.group(0)  # Already has encoding
        
        # Add encoding and errors parameters before the closing parenthesis
        # Insert before timeout if present, otherwise at the end
        if 'timeout=' in call_content:
            # Insert before timeout
            call_content = call_content.replace(
                'timeout=',
                "encoding='utf-8',\n                errors='replace',\n                timeout="
            )
        else:
            # Add at the end
            call_content += ",\n                encoding='utf-8',\n                errors='replace'"
        
        return call_content + closing_paren
    
    # Apply the pattern
    fixed_content = re.sub(pattern, add_encoding, content, flags=re.DOTALL)
    
    return fixed_content


def main():
    sandbox_file = r"src\modules\sandbox.py"
    
    print("=" * 80)
    print("FIXING ENCODING ISSUES IN SANDBOX.PY")
    print("=" * 80)
    
    # Read the file
    print(f"\n[1] Reading {sandbox_file}...")
    try:
        with open(sandbox_file, 'r', encoding='utf-8') as f:
            content = f.read()
        print(f"✓ Read {len(content)} characters")
    except Exception as e:
        print(f"✗ Failed to read file: {e}")
        return 1
    
    # Count subprocess.run calls before fix
    print("\n[2] Analyzing subprocess.run calls...")
    subprocess_count = len(re.findall(r'subprocess\.run\(', content))
    text_true_count = len(re.findall(r'subprocess\.run\([^)]*text=True', content, re.DOTALL))
    with_encoding = len(re.findall(r'subprocess\.run\([^)]*encoding=', content, re.DOTALL))
    
    print(f"  Total subprocess.run calls: {subprocess_count}")
    print(f"  Calls with text=True: {text_true_count}")
    print(f"  Calls already with encoding: {with_encoding}")
    print(f"  Calls needing fix: {text_true_count - with_encoding}")
    
    # Apply fixes
    print("\n[3] Applying encoding fixes...")
    fixed_content = fix_subprocess_encoding(content)
    
    # Count after fix
    new_with_encoding = len(re.findall(r'subprocess\.run\([^)]*encoding=', fixed_content, re.DOTALL))
    print(f"  Calls with encoding after fix: {new_with_encoding}")
    print(f"  Fixed calls: {new_with_encoding - with_encoding}")
    
    # Backup original file
    backup_file = sandbox_file + ".backup"
    print(f"\n[4] Creating backup: {backup_file}")
    try:
        with open(backup_file, 'w', encoding='utf-8') as f:
            f.write(content)
        print("✓ Backup created")
    except Exception as e:
        print(f"✗ Failed to create backup: {e}")
        return 1
    
    # Write fixed content
    print(f"\n[5] Writing fixed content to {sandbox_file}...")
    try:
        with open(sandbox_file, 'w', encoding='utf-8') as f:
            f.write(fixed_content)
        print("✓ File updated successfully")
    except Exception as e:
        print(f"✗ Failed to write file: {e}")
        print("  Restoring from backup...")
        try:
            with open(backup_file, 'r', encoding='utf-8') as f:
                backup_content = f.read()
            with open(sandbox_file, 'w', encoding='utf-8') as f:
                f.write(backup_content)
            print("  ✓ Restored from backup")
        except:
            print("  ✗ Failed to restore backup")
        return 1
    
    print("\n" + "=" * 80)
    print("ENCODING FIX COMPLETE!")
    print("=" * 80)
    print(f"\n✓ Fixed {new_with_encoding - with_encoding} subprocess.run calls")
    print(f"✓ Backup saved to: {backup_file}")
    print("\nAll subprocess.run calls with text=True now include:")
    print("  - encoding='utf-8'")
    print("  - errors='replace'")
    print("\nThis will fix UnicodeDecodeError when reading output from Docker/VirtualBox")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
