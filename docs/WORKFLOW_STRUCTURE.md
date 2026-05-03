# מבנה ה-Workflow המלא - LangGraph CVE Exploitation System

## סקירה כללית

המערכת מבצעת תהליך מקצה לקצה של ניתוח CVE ויצירת exploit.
כל CVE עובר דרך **7 שלבים עיקריים**, עם בדיקות תקינות בכל שלב.

- אם בשלב כלשהו נכשל → המערכת עוברת ל-`handle_error` ומסתיימת
- אם הכל מצליח → המערכת מגיעה ל-`workflow_complete`

---

## מבנה השלבים

```
START (התחלה)
   ↓
┌──────────────────────────────────────────────────────────────────┐
│ STEP 1: check_connections                                        │
│ ══════════════════════════════════════════════════════════       │
│                                                                  │
│ מטרה: בדיקת חיבור ל-APIs הנדרשים                                │
│                                                                  │
│ פעולות:                                                          │
│   1. בדיקת חיבור ל-Ollama LLM (localhost:11434)                 │
│   2. שליחת "ping" וקבלת "pong"                                  │
│   3. אימות שה-model gpt-oss:20b זמין                            │
│                                                                  │
│ תוצאות אפשריות:                                                  │
│   ✅ SUCCESS → connections_ok = True → עבור ל-STEP 2            │
│   ❌ FAILED  → connections_ok = False → עבור ל-handle_error      │
│                                                                  │
│ State: CHECKING_CONNECTIONS → CONNECTION_SUCCESS/FAILED         │
└──────────────────────────────────────────────────────────────────┘
   ↓
┌──────────────────────────────────────────────────────────────────┐
│ STEP 2: load_cve                                                 │
│ ══════════════════════════════════════════════════════════════   │
│                                                                  │
│ מטרה: טעינת נתוני CVE מהמאגר + בדיקת תמיכה                     │
│                                                                  │
│ פעולות:                                                          │
│   1. טעינת CVEDatabase מ-nvd_cves_all.jsonl (187K CVEs)        │
│   2. חיפוש CVE לפי ID (למשל CVE-2008-0888)                     │
│   3. חילוץ CWE מנתוני ה-CVE                                      │
│   4. ✨ VALIDATION: בדיקה שה-CWE נתמך במערכת                     │
│   5. אם CWE לא נתמך (SQL Injection, XSS וכו') → דחייה מיידית  │
│                                                                  │
│ נתונים שנטענים ל-context:                                        │
│   - cve_data: כל נתוני ה-CVE (תיאור, CVSS, references)         │
│   - cve_id: CVE-XXXX-XXXX                                       │
│                                                                  │
│ בדיקת תמיכה:                                                     │
│   - רשימת CWEs נתמכים: CWE-119,120,121,122,125,787 (Buffer)   │
│                         CWE-134 (Format String)                 │
│   - אם CVE לא מכיל אחד מאלה → שגיאה מפורטת ודחייה               │
│                                                                  │
│ תוצאות אפשריות:                                                  │
│   ✅ CVE נמצא וה-CWE נתמך → עבור ל-STEP 3                       │
│   ❌ CVE לא נמצא / CWE לא נתמך → עבור ל-handle_error           │
│                                                                  │
│ State: LOADING_CVE → CVE_LOADED/CVE_LOAD_FAILED                │
└──────────────────────────────────────────────────────────────────┘
   ↓
┌──────────────────────────────────────────────────────────────────┐
│ STEP 3: build_prompt                                             │
│ ══════════════════════════════════════════════════════════════   │
│                                                                  │
│ מטרה: בניית prompts דינמיים עם Orchestrator                     │
│                                                                  │
│ פעולות:                                                          │
│   1. אתחול PromptOrchestrator                                   │
│   2. חילוץ CWE מנתוני ה-CVE                                      │
│   3. מיפוי CWE ← Expert Profile + Vulnerability Logic           │
│      לדוגמה:                                                     │
│      CWE-119 → binary_exploitation.txt + buffer_overflow.txt   │
│      CWE-134 → binary_exploitation.txt + format_string.txt     │
│   4. טעינת תוכן הקבצים                                           │
│   5. הרכבת System Prompt (expert profile + context)            │
│   6. הרכבת User Prompt (CVE details + methodology)             │
│                                                                  │
│ System Prompt מכיל:                                              │
│   - תיאור תפקיד המומחה (Binary Exploitation Expert)            │
│   - הידע והכישורים שלו                                           │
│   - ההנחיות לעבודה אתית (authorized research)                  │
│                                                                  │
│ User Prompt מכיל:                                                │
│   - נתוני ה-CVE (תיאור, CVSS, references)                      │
│   - מתודולוגיית התקיפה (buffer overflow techniques)            │
│   - דרישות המשימה (POC code, comments, Python+pwntools)        │
│                                                                  │
│ נתונים שנוספו ל-context:                                         │
│   - system_prompt: ה-prompt למערכת                              │
│   - user_prompt: ה-prompt למשתמש                                │
│   - cwe_id: CWE-XXX שחולץ                                       │
│   - prompt_metadata: {category, expert_profile, logic_file}    │
│                                                                  │
│ תוצאות אפשריות:                                                  │
│   ✅ Prompts נבנו בהצלחה → עבור ל-STEP 4                        │
│   ❌ שגיאה בבנייה → עבור ל-handle_error                         │
│                                                                  │
│ State: BUILDING_PROMPT → PROMPT_BUILT/PROMPT_BUILD_FAILED      │
└──────────────────────────────────────────────────────────────────┘
   ↓
┌──────────────────────────────────────────────────────────────────┐
│ STEP 4: validate_file                                            │
│ ══════════════════════════════════════════════════════════════   │
│                                                                  │
│ מטרה: בדיקת קובץ פגיע (אופציונלי - רק אם הועבר file_path)      │
│                                                                  │
│ פעולות:                                                          │
│   1. בדיקה אם file_path קיים                                     │
│   2. אם לא - דילוג (CVE-only mode)                              │
│   3. אם כן - קריאת תוכן הקובץ                                    │
│   4. אחסון ב-file_content                                        │
│                                                                  │
│ שימוש:                                                            │
│   - במצב רגיל: רק CVE ID                                         │
│   - במצב מתקדם: CVE ID + vulnerable.c file                      │
│                                                                  │
│ תוצאות אפשריות:                                                  │
│   ✅ אין file או file תקין → עבור ל-STEP 5                     │
│   ❌ file לא תקין → עבור ל-handle_error                         │
│                                                                  │
│ State: VALIDATING_FILE → VALIDATION_SUCCESS/FAILED             │
└──────────────────────────────────────────────────────────────────┘
   ↓
┌──────────────────────────────────────────────────────────────────┐
│ STEP 5: analyze_vulnerability                                    │
│ ══════════════════════────════════════════════────════════════   │
│                                                                  │
│ מטרה: ניתוח הפגיעות על ידי LLM עם ה-prompts הדינמיים            │
│                                                                  │
│ פעולות:                                                          │
│   1. שליחת system_prompt ו-user_prompt ל-LLM                    │
│   2. ה-LLM מקבל:                                                 │
│      - תפקיד כ"Binary Exploitation Expert"                     │
│      - פרטי CVE מלאים                                            │
│      - מתודולוגיית buffer overflow                              │
│   3. ה-LLM מנתח את הפגיעות                                       │
│   4. החזרת תוצאות הניתוח                                         │
│                                                                  │
│ קריאה:                                                            │
│   sendToLLMWithDynamicPrompt(system_prompt, user_prompt)       │
│   ↓                                                              │
│   Ollama API (localhost:11434)                                  │
│   ↓                                                              │
│   Model: gpt-oss:20b                                            │
│   ↓                                                              │
│   Response: ניתוח טכני של הפגיעות                               │
│                                                                  │
│ נתונים שנשמרים:                                                  │
│   - llm_response: תשובת ה-LLM המלאה                             │
│   - vulnerability_data: נתונים מובנים                           │
│                                                                  │
│ זמן ביצוע משוער: 30-60 שניות                                     │
│                                                                  │
│ תוצאות אפשריות:                                                  │
│   ✅ ניתוח הושלם → עבור ל-STEP 6                                │
│   ❌ LLM נכשל / סירב → עבור ל-handle_error                      │
│                                                                  │
│ State: ANALYZING_VULNERABILITY → ANALYSIS_SUCCESS/FAILED       │
└──────────────────────────────────────────────────────────────────┘
   ↓
┌──────────────────────────────────────────────────────────────────┐
│ STEP 6: create_attack_script                                     │
│ ══════════════════════════════════════════════════════════════   │
│                                                                  │
│ מטרה: יצירת קוד exploit עובד על ידי Agent                       │
│                                                                  │
│ פעולות:                                                          │
│   1. העברת נתוני הפגיעות + prompts ל-Agent                      │
│   2. ה-Agent מייצר exploit code:                                │
│      - בפייטון (עם pwntools)                                    │
│      - עם הערות מפורטות                                          │
│      - Proof-of-Concept מלא                                     │
│   3. החזרת הקוד                                                  │
│                                                                  │
│ קריאה:                                                            │
│   generateExploitWithDynamicPrompt(...)                         │
│   ↓                                                              │
│   Agent API                                                      │
│   ↓                                                              │
│   Python exploit code                                            │
│                                                                  │
│ נתונים שנשמרים:                                                  │
│   - attack_script: קוד ה-exploit המלא                           │
│                                                                  │
│ זמן ביצוע משוער: 30-60 שניות                                     │
│                                                                  │
│ תוצאות אפשריות:                                                  │
│   ✅ Exploit נוצר → עבור ל-STEP 7                               │
│   ❌ Agent נכשל → עבור ל-handle_error                           │
│                                                                  │
│ State: CREATING_SCRIPT → SCRIPT_SUCCESS/SCRIPT_FAILED          │
└──────────────────────────────────────────────────────────────────┘
   ↓
┌──────────────────────────────────────────────────────────────────┐
│ STEP 7: execute_in_sandbox                                       │
│ ══════════════════════════════════════════════════════════════   │
│                                                                  │
│ מטרה: הרצת ה-exploit בסביבת Sandbox מבודדת                      │
│                                                                  │
│ פעולות:                                                          │
│   1. בחירת Sandbox (Docker / VirtualBox / E2B Cloud)           │
│   2. העברת הקוד + קובץ פגיע ל-Sandbox                           │
│   3. הרצת ה-exploit                                              │
│   4. איסוף תוצאות (stdout, stderr, exit code)                  │
│   5. ניקוי הסביבה                                                │
│                                                                  │
│ Sandboxes זמינים:                                                │
│   🐳 Docker: קונטיינר מבודד עם OS מינימלי                      │
│   🖥️ VirtualBox: VM מלא עם Debian/Ubuntu                       │
│   ☁️ E2B Cloud: סביבת ענן מבוזרת                               │
│                                                                  │
│ נתונים שנשמרים:                                                  │
│   - sandbox_result: פלט ההרצה                                   │
│   - attack_result: סטטוס ההצלחה                                │
│                                                                  │
│ זמן ביצוע משוער: 10-30 שניות                                     │
│                                                                  │
│ תוצאות אפשריות:                                                  │
│   ✅ Exploit רץ בהצלחה → עבור ל-workflow_complete              │
│   ❌ Sandbox נכשל → עבור ל-handle_error                         │
│                                                                  │
│ State: EXECUTING_IN_SANDBOX → SANDBOX_SUCCESS/FAILED           │
└──────────────────────────────────────────────────────────────────┘
   ↓
┌──────────────────────────────────────────────────────────────────┐
│ workflow_complete (סיום מוצלח)                                   │
│ ══════════════════════════════════════════════════════════════   │
│                                                                  │
│ State: COMPLETED                                                │
└──────────────────────────────────────────────────────────────────┘
   ↓
END
```

---

## זרימת המידע בין השלבים

`AgentContext` נושא את כל המידע:

| שלב | נתונים שנוספים |
|-----|----------------|
| Step חיבור ל-APIs | `connections_ok` |
| Step 2 | `cve_data`, `cve_id` |
| Step 3 | `system_prompt`, `user_prompt`, `cwe_id`, `prompt_metadata` |
| Step 4 | `file_content` (אופציונלי) |
| Step 5 | `llm_response`, `vulnerability_data` |
| Step 6 | `attack_script` |
| Step 7 | `sandbox_result`, `attack_result` |

---

## דוגמה למעבר מלא

**CVE-2008-0888 (Buffer Overflow):**

```
1. check_connections
   ✅ Ollama: Connected
   → connections_ok = True

2. load_cve
   ✅ Found: CVE-2008-0888
   ✅ CWE: CWE-119 (Buffer Overflow)
   ✅ Validation: SUPPORTED
   → cve_data = {...}

3. build_prompt
   ✅ Mapping: CWE-119 → binary_exploitation.txt + buffer_overflow.txt
   → system_prompt = "You are Binary Exploitation Expert..."
   → user_prompt = "CVE-2008-0888: Buffer overflow in..."

4. validate_file
   ⚠️ No file provided → Skipped (CVE-only mode)

5. analyze_vulnerability
   ⏳ Sending to LLM... (30s)
   ✅ Response received

6. create_attack_script
   ⏳ Generating exploit... (30s)
   ✅ Python code generated

7. execute_in_sandbox
   ⏳ Running in Docker... (15s)
   ✅ Execution completed

8. workflow_complete
   ✅ All steps completed
```

---

## קונפיגורציה

| רכיב | נתיב |
|------|------|
| הגדרות CWE | `src/config/cwe_mapping.json` |
| מאגר CVE | `data/nvd_cves_all.jsonl` (187,714 CVEs) |
| Expert Profiles | `src/expert_profiles/*.txt` |
| Vulnerability Logic | `src/vulnerability_logic/*.txt` |

**CWEs נתמכים:**
- CWE-119: Buffer Overflow
- CWE-120: Buffer Copy without Checking Size
- CWE-121: Stack-based Buffer Overflow
- CWE-122: Heap-based Buffer Overflow
- CWE-125: Out-of-bounds Read
- CWE-787: Out-of-bounds Write
- CWE-134: Format String

**סה"כ CVEs זמינים:** ~3,000

---

## סיכום

✅ **7 שלבים עיקריים**  
✅ **בדיקת תקינות בכל שלב**  
✅ **מעבר חלק עם AgentContext**  
✅ **תמיכה ב-Buffer Overflow ו-Format String בלבד**  
✅ **דחייה אוטומטית של CVEs לא נתמכים**  
✅ **Prompts דינמיים לפי סוג הפגיעות**  
✅ **הרצה מבודדת ב-Sandbox**

**המערכת מוכנה לשימוש! 🚀**
