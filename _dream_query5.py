import sqlite3, json, datetime

conn = sqlite3.connect(r'C:\Users\cyber\.local\share\mimocode\mimocode.db')
c = conn.cursor()

# 1. Check part table structure
print("=" * 80)
print("PART TABLE STRUCTURE (first few rows from Salesforce session)")
print("=" * 80)
c.execute("""
    SELECT p.id, p.message_id, p.data
    FROM part p
    WHERE p.session_id = 'ses_083e78d42ffezgDFE7OAUl6CSq'
    ORDER BY p.time_created ASC
    LIMIT 5
""")
for r in c.fetchall():
    d = json.loads(r[2])
    print(f"  part_id={r[0][:20]} msg_id={r[1][:20]}")
    print(f"  keys: {list(d.keys())}")
    print(f"  type: {d.get('type', 'N/A')}")
    if d.get('type') == 'text':
        print(f"  text: {str(d.get('text', ''))[:200]}")
    elif d.get('type') == 'tool':
        print(f"  tool: {d.get('tool', 'N/A')}")
    print(f"  data preview: {r[2][:200]}")
    print()

# 2. Get user turn text content from Salesforce session
print("=" * 80)
print("USER TURNS TEXT CONTENT (Salesforce session)")
print("=" * 80)
c.execute("""
    SELECT m.time_created, p.data
    FROM message m
    JOIN part p ON p.message_id = m.id
    WHERE m.session_id = 'ses_083e78d42ffezgDFE7OAUl6CSq'
      AND json_extract(m.data, '$.role') = 'user'
      AND json_extract(p.data, '$.type') = 'text'
    ORDER BY m.time_created ASC
""")
for r in c.fetchall():
    ts = datetime.datetime.fromtimestamp(r[0]/1000).strftime('%Y-%m-%d %H:%M')
    d = json.loads(r[1])
    text = d.get('text', '')
    if text.strip() and len(text.strip()) > 5:
        print(f"  [{ts}] {text[:300]}")
        print()

# 3. Get user turns text content from jarvis sessions
print("=" * 80)
print("USER TURNS TEXT CONTENT (jarvis sessions)")
print("=" * 80)
c.execute("""
    SELECT m.time_created, s.id, s.title, p.data
    FROM message m
    JOIN part p ON p.message_id = m.id
    JOIN session s ON s.id = m.session_id
    WHERE (s.directory LIKE '%jarvis%' OR s.directory LIKE '%antigravity%')
      AND json_extract(m.data, '$.role') = 'user'
      AND json_extract(p.data, '$.type') = 'text'
    ORDER BY m.time_created DESC
    LIMIT 30
""")
for r in c.fetchall():
    ts = datetime.datetime.fromtimestamp(r[0]/1000).strftime('%Y-%m-%d %H:%M')
    d = json.loads(r[3])
    text = d.get('text', '')
    if text.strip() and len(text.strip()) > 5:
        print(f"  [{ts}] [{r[1][:20]}] {text[:300]}")
        print()

# 4. Get all user messages with text content
print("=" * 80)
print("ALL USER TEXT MESSAGES (all projects)")
print("=" * 80)
c.execute("""
    SELECT m.time_created, s.id, s.directory, p.data
    FROM message m
    JOIN part p ON p.message_id = m.id
    JOIN session s ON s.id = m.session_id
    WHERE json_extract(m.data, '$.role') = 'user'
      AND json_extract(p.data, '$.type') = 'text'
      AND s.title NOT LIKE 'checkpoint-writer%'
    ORDER BY m.time_created DESC
    LIMIT 40
""")
for r in c.fetchall():
    ts = datetime.datetime.fromtimestamp(r[0]/1000).strftime('%Y-%m-%d %H:%M')
    d = json.loads(r[3])
    text = d.get('text', '')
    if text.strip() and len(text.strip()) > 5:
        short_dir = (r[2] or '').replace('C:\\Users\\cyber\\', '')
        print(f"  [{ts}] [{short_dir[:30]}] {text[:300]}")
        print()

conn.close()
