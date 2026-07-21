import sqlite3, json, datetime

conn = sqlite3.connect(r'C:\Users\cyber\.local\share\mimocode\mimocode.db')
c = conn.cursor()

# 1. Get ALL user messages from ses_083e78d42ffezgDFE7OAUl6CSq (Salesforce session)
print("=" * 80)
print("ALL USER MESSAGES FROM SALESFORCE SESSION")
print("=" * 80)
c.execute("""
    SELECT json_extract(m.data, '$.content'), m.time_created
    FROM message m
    WHERE m.session_id = 'ses_083e78d42ffezgDFE7OAUl6CSq'
      AND json_extract(m.data, '$.role') = 'user'
    ORDER BY m.time_created ASC
""")
for r in c.fetchall():
    ts = datetime.datetime.fromtimestamp(r[1]/1000).strftime('%Y-%m-%d %H:%M')
    content = (r[0] or '').strip()
    if content and len(content) > 10:
        print(f"  [{ts}] {content[:300]}")
        print()

# 2. Get user messages from ses_0b9bf8b38ffevVA319LdE50O3b (Security workspace)
print("\n" + "=" * 80)
print("SECURITY WORKSPACE SESSION USER MESSAGES")
print("=" * 80)
c.execute("""
    SELECT json_extract(m.data, '$.content'), m.time_created
    FROM message m
    WHERE m.session_id = 'ses_0b9bf8b38ffevVA319LdE50O3b'
      AND json_extract(m.data, '$.role') = 'user'
    ORDER BY m.time_created ASC
""")
for r in c.fetchall():
    ts = datetime.datetime.fromtimestamp(r[1]/1000).strftime('%Y-%m-%d %H:%M')
    content = (r[0] or '').strip()
    if content and len(content) > 10:
        print(f"  [{ts}] {content[:300]}")
        print()

# 3. Get user messages from ses_0c58369e4ffeVsDC9DOo9icNuc (general web nav test)
print("\n" + "=" * 80)
print("GENERAL WEB NAV SESSION USER MESSAGES")
print("=" * 80)
c.execute("""
    SELECT json_extract(m.data, '$.content'), m.time_created
    FROM message m
    WHERE m.session_id = 'ses_0c58369e4ffeVsDC9DOo9icNuc'
      AND json_extract(m.data, '$.role') = 'user'
    ORDER BY m.time_created ASC
""")
for r in c.fetchall():
    ts = datetime.datetime.fromtimestamp(r[1]/1000).strftime('%Y-%m-%d %H:%M')
    content = (r[0] or '').strip()
    if content and len(content) > 10:
        print(f"  [{ts}] {content[:300]}")
        print()

# 4. Get the write/edit tool calls from Salesforce session - focus on key files modified
print("\n" + "=" * 80)
print("KEY FILES MODIFIED IN SALESFORCE SESSION")
print("=" * 80)
c.execute("""
    SELECT json_extract(p.data, '$.tool'), json_extract(json_extract(p.data, '$.state.input'), '$.file_path')
    FROM message m
    JOIN part p ON p.message_id = m.id
    WHERE m.session_id = 'ses_083e78d42ffezgDFE7OAUl6CSq'
      AND json_extract(p.data, '$.type') = 'tool'
      AND json_extract(p.data, '$.tool') IN ('write', 'edit')
    ORDER BY m.time_created ASC
""")
seen = set()
for r in c.fetchall():
    fp = r[1] or ''
    short = fp.replace('C:\\Users\\cyber\\API\\sf_api_security_tester\\', '')
    key = f"{r[0]}:{short}"
    if key not in seen:
        seen.add(key)
        print(f"  {r[0]:5s} {short}")

# 5. Check for error patterns in assistant messages from Salesforce session
print("\n" + "=" * 80)
print("NOTABLE ASSISTANT TEXT FROM SALESFORCE SESSION (first 20)")
print("=" * 80)
c.execute("""
    SELECT json_extract(p.data, '$.text'), m.time_created
    FROM message m
    JOIN part p ON p.message_id = m.id
    WHERE m.session_id = 'ses_083e78d42ffezgDFE7OAUl6CSq'
      AND json_extract(p.data, '$.type') = 'text'
      AND json_extract(m.data, '$.role') = 'assistant'
      AND length(json_extract(p.data, '$.text')) > 50
    ORDER BY m.time_created ASC
    LIMIT 20
""")
for r in c.fetchall():
    ts = datetime.datetime.fromtimestamp(r[1]/1000).strftime('%Y-%m-%d %H:%M')
    text = (r[0] or '')[:250]
    print(f"  [{ts}] {text}")
    print()

conn.close()
