# Rules

Rules version 2026.11.2. Written by `tests/make_docs.py` from the rules files and the language files.

| Id | Severity | What it means | בעברית |
| --- | --- | --- | --- |
| SR-IN-001 | red | Contains a link that points at your files outside the skill | מכיל קישור שמצביע לקבצים שלך מחוץ לסקיל |
| SR-IN-002 | red | Two files share one name, differing only by letter case or Unicode form | שני קבצים עם אותו שם, בהבדל של אותיות גדולות או צורת Unicode |
| SR-IN-003 | red | Far larger than any normal skill | גדול בהרבה מכל סקיל רגיל |
| SR-IN-011 | red | An archive that tries to write outside its folder, or a damaged archive | ארכיון שמנסה לכתוב מחוץ לתיקייה, או ארכיון פגום |
| SR-RL-01 | red | Reads your secret files (SSH keys, passwords, access tokens) | קורא קובצי סודות שלך (מפתחות SSH, סיסמאות, אסימוני גישה) |
| SR-RL-02 | red | Downloads code from the network and runs it | מוריד קוד מהרשת ומריץ אותו |
| SR-RL-04 | red | Ships an executable with no source code | מכיל קובץ הרצה בלי קוד מקור |
| SR-RL-05 | red | An auto-run component writes to the agent's settings or to another skill | רכיב שרץ לבד כותב להגדרות של הסוכן או לסקיל אחר |
| SR-RL-06 | red | Tells the agent to hide actions, skip approvals or send data quietly | מורה לסוכן להסתיר פעולות, לדלג על אישורים או לשלוח מידע בשקט |
| SR-RL-07 | red | Contains hidden text that you cannot see and the agent can | מכיל טקסט מוסתר שאתה לא רואה והסוכן כן |
| SR-RL-08 | red | Promises one thing and does another | מבטיח דבר אחד ועושה דבר אחר |
| SR-RL-09 | red (reserved, never reported) | Reserved rule: an upstream update that was not checked yet | כלל שמור: עדכון במקור שעוד לא נבדק |
| SR-RL-10 | red | Ships a file that poses as a built-in Python module | מכיל קובץ שמתחזה לרכיב מובנה של Python |
| SR-RL-12 | red | Tells the agent to load instructions from a network address at run time | מורה לסוכן לטעון הוראות מכתובת ברשת בזמן ריצה |
| SR-RL-13 | red | An auto-run component downloads code and runs it | רכיב שרץ לבד מוריד קוד ומריץ אותו |
| SR-RL-14 | red | Adds a command named like a well-known tool | מוסיף פקודה בשם של כלי מוכר |
| SR-RL-16 | red | Shows a dialog that asks for your password | מציג חלון שמבקש את הסיסמה שלך |
| SR-CD-001 | high | Contains code in a language the scan does not analyse | מכיל קוד בשפה שהבדיקה לא מנתחת |
| SR-CD-003 | high | Runs code that is built at run time | מריץ קוד שנבנה בזמן ריצה |
| SR-CD-004 | high | Downloads and runs an installer script from the network | מוריד ומריץ סקריפט התקנה מהרשת |
| SR-CD-006 | high | Removes the macOS quarantine mark from a file | מסיר את סימון ההסגר של macOS מקובץ |
| SR-DF-001 | high | Contacts a network address decided at run time, with no explanation in the docs | פונה לכתובת ברשת שנקבעת בזמן ריצה, בלי שום הסבר בתיעוד |
| SR-DF-004 | high | Contacts a server that the docs never mention | פונה לשרת שלא מוזכר בשום מקום בתיעוד |
| SR-DF-014 | high | Points at a tunnelling service or a throwaway collection service | מפנה לשירות מנהור או לשירות איסוף זמני |
| SR-DF-016 | high | Redirects the package manager to another registry | מפנה את מנהל החבילות לשרת חבילות אחר |
| SR-DF-018 | high | Collects every environment variable and writes it to output or the network | אוסף את כל משתני הסביבה ומוציא אותם לפלט או לרשת |
| SR-DF-019 | high | Points at a raw IP address instead of a named server | פונה לכתובת IP גולמית במקום לשם של שרת |
| SR-FAIL-CLOSED | high | A scan stage failed because of the skill's own content | שלב בבדיקה נכשל בגלל תוכן הסקיל |
| SR-IN-004 | high | Too large to scan in full | גדול מכדי לסרוק את כולו |
| SR-IN-010 | high | Ships compiled Python next to its source | מכיל קוד Python מקומפל לצד קוד המקור |
| SR-RL-03 | high | Runs code hidden inside an unreadable string | מריץ קוד שמוסתר בתוך מחרוזת לא קריאה |
| SR-RL-15 | high | Runs a module inside the agent's own process without declaring it | מריץ מודול בתוך התהליך של הסוכן בלי להצהיר עליו |
| SR-SF-001 | high | An auto-run component that cannot be analysed | רכיב שרץ לבד ואי אפשר לנתח אותו |
| SR-SF-002 | high | A hook runs a file outside the plugin folder | hook שמריץ קובץ מחוץ לתיקיית הפלאגין |
| SR-SF-006 | high | An auto-run component pulls the latest version of a package every time | רכיב שרץ לבד מוריד בכל פעם את הגרסה האחרונה של חבילה מהרשת |
| SR-SF-007 | high | A script writes to the agent's settings or to the skills folder | סקריפט שכותב להגדרות של הסוכן או לתיקיית הסקילים |
| SR-SF-008 | high | Starts an agent with approvals switched off | מפעיל סוכן במצב שמדלג על אישורים |
| SR-SF-011 | high | A hook answers permission requests for you | hook שמאשר בקשות הרשאה במקומך |
| SR-ST-006 | high | A settings file that cannot be read safely | קובץ הגדרות שאי אפשר לקרוא בבטחה |
| SR-TX-003 | high | Contains a real secret (a key or token) in its files | מכיל סוד אמיתי (מפתח או אסימון) בתוך הקבצים |
| SR-TX-008 | high | The instructions point at a password-protected archive | ההוראות מפנות לארכיון מוגן בסיסמה |
| SR-TX-009 | high | The instructions require installing software from a free-hosting site or a short link | ההוראות דורשות להתקין תוכנה מאתר באירוח חינמי או מקישור מקוצר |
| SR-CD-002 | medium | A Python file that could not be fully analysed | קובץ Python שלא ניתן לניתוח מלא |
| SR-CD-005 | medium | Bundled or minified code that is hard to read | קוד דחוס או מאוגד שקשה לקרוא |
| SR-CL-001 | medium | A statement in the docs does not fully match the code | הצהרה בתיעוד שלא לגמרי תואמת את הקוד |
| SR-DF-002 | medium | An auto-run component the docs do not mention | רכיב שרץ לבד ולא מוזכר בתיעוד |
| SR-DF-003 | medium | Writes outside its own folder without saying so | כותב מחוץ לתיקייה שלו בלי לציין זאת |
| SR-DF-005 | medium | Installs packages at run time without saying so | מתקין חבילות בזמן ריצה בלי לציין זאת |
| SR-DF-009 | medium | Reads a .env file | קורא קובץ env |
| SR-DF-010 | medium | Refers to a path of secret files | מתייחס לנתיב של קובצי סודות |
| SR-DF-012 | medium | The capabilities file is not valid, or not in the expected form | קובץ הצהרת היכולות לא תקין, או לא בצורה המצופה |
| SR-DF-015 | medium | Reads every environment variable | קורא את כל משתני הסביבה |
| SR-DF-020 | medium | Installs or changes skills or agent settings, as its capabilities file says | מתקין או משנה סקילים או הגדרות של הסוכן, כפי שכתוב בקובץ היכולות שלו |
| SR-IN-006 | medium | Contains an archive that was not opened | מכיל קובץ ארכיון שלא נפתח |
| SR-IN-008 | medium | Contains an unidentified binary file | מכיל קובץ בינארי לא מזוהה |
| SR-RL-11 | medium | Needs a paid service that the docs do not mention | דורש שירות בתשלום שלא מוזכר בתיעוד |
| SR-SF-003 | medium | Declares hooks that stay active for the whole session | מגדיר hooks שפעילים לאורך כל הסשן |
| SR-SF-005 | medium | Runs a script while npm packages install | מריץ סקריפט בזמן התקנת חבילות npm |
| SR-SF-010 | medium | A script writes into a project's .claude folder | סקריפט שכותב לתיקיית .claude של פרויקט |
| SR-ST-007 | medium | No SKILL.md was found | לא נמצא קובץ SKILL.md |
| SR-TX-001 | medium | An invisible character in the text | תו בלתי נראה בתוך הטקסט |
| SR-TX-002 | medium | Tells the agent to carry on without asking | מורה לסוכן להמשיך בלי לבקש אישור |
| SR-TX-005 | medium | The instructions tell the agent to download and run a well-known installer | ההוראות אומרות לסוכן להוריד ולהריץ סקריפט התקנה של כלי מוכר |
| SR-TX-006 | medium | A document in the package suggests downloading and running a script from the network | מסמך בחבילה מציע להוריד ולהריץ סקריפט מהרשת |
| SR-TX-007 | medium | Tells the agent to follow instructions found in outside content | מורה לסוכן לפעול לפי הוראות שיימצאו בתוכן חיצוני |
| SR-DF-008 | low | Reads a secret from the environment | קורא סוד ממשתני הסביבה |
| SR-DF-011 | low | Contacts a network address decided at run time | פונה לכתובת ברשת שנקבעת בזמן ריצה |
| SR-IN-005 | low | Contains a symbolic link, which was not followed | מכיל קישור סימבולי, שלא נפתח |
| SR-IN-007 | low | Contains documents whose text cannot be scanned (PDF, Office) | מכיל מסמכים שאי אפשר לסרוק בהם טקסט (PDF, Office) |
| SR-IN-009 | low | Large text file, only the first megabyte was scanned | קובץ טקסט גדול, נסרק רק המגה הראשון |
| SR-SF-004 | low | Pre-approves Bash with no restriction | מאשר מראש את Bash בלי הגבלה |
| SR-ST-001 | low | SKILL.md is missing a name or a description | ל-SKILL.md חסרים שם או תיאור |
| SR-ST-008 | low | The frontmatter was not read in full | ה-frontmatter לא נקרא במלואו |
| SR-DF-006 | info | Declared, but not found in the code | מוצהר, אבל לא נמצא בקוד |
| SR-DF-007 | info | Reads standard input | קורא קלט סטנדרטי |
| SR-DF-013 | info | The instructions lead the agent to a connected service | ההוראות מובילות את הסוכן לשירות מחובר |
| SR-SF-009 | info | Has auto-run components | יש רכיבים שרצים לבד |
| SR-ST-002 | info | The skill name is invalid or does not match its folder | שם הסקיל לא תקין או לא תואם את שם התיקייה |
| SR-ST-003 | info | The description is too long or contains angle brackets | התיאור ארוך מדי או מכיל סוגריים משולשים |
| SR-ST-004 | info | SKILL.md is longer than 500 lines | SKILL.md ארוך מ-500 שורות |
| SR-ST-005 | info | SKILL.md links to a file that does not exist | SKILL.md מפנה לקובץ שלא קיים |
| SR-TX-004 | info | Mentions a prompt-injection phrase as an example | מזכיר ביטוי של הזרקת הוראות כדוגמה |

A red line ends in "do not install". High ends in "caution". Medium and low are notes. Info appears only under details.

## Rules of the trial run

These describe what a skill's own commands did inside the sandbox, not what its files contain.

| Id | Severity | What it means | בעברית |
| --- | --- | --- | --- |
| SR-TR-001 | red | Read your secrets (keys, passwords, access tokens) | קרא את הסודות שלך (מפתחות, סיסמאות, אסימוני גישה) |
| SR-TR-002 | red | Took the content of a secret and passed it on | לקח תוכן של סוד והעביר אותו הלאה |
| SR-TR-004 | red | Changed your settings, start-up files or secrets | שינה הגדרות, קובצי אתחול או סודות שלך |
| SR-TR-003 | high | Tried to reach a server it does not declare | ניסה לפנות לשרת שהוא לא מצהיר עליו |
| SR-TR-005 | high | Tried to install software | ניסה להתקין תוכנה |
| SR-TR-006 | high | Looked at sensitive files (project keys, shell history, the conversation) or looked for secrets | הסתכל בקבצים רגישים (מפתחות הפרויקט, היסטוריית הטרמינל, השיחה) או חיפש סודות |
| SR-TR-010 | high | Tried to change the system (administrator rights, desktop scripting, quarantine, containers) | ניסה לשנות את המערכת (הרשאות מנהל, שליטה בשולחן העבודה, הסרת הסגר, קונטיינרים) |
| SR-TR-007 | medium | Wrote or removed files in your home or project folder | כתב או מחק קבצים בתיקיית הבית או בתיקיית הפרויקט |
| SR-TR-011 | medium | Called an installer where you can see it coming | קרא לתוכנת התקנה במקום שאפשר לצפות אותו |
| SR-TR-012 | medium | Read sensitive files that its own documents say it reads | קרא קבצים רגישים שהתיעוד שלו אומר שהוא קורא |
| SR-TR-013 | medium | Tried to open a web page in your browser | ניסה לפתוח דף אינטרנט בדפדפן שלך |
| SR-TR-008 | low | Tried to reach a server it declares | ניסה לפנות לשרת שהוא מצהיר עליו |
| SR-TR-009 | info | Part of the run could not be observed | חלק מהריצה לא נצפה |
