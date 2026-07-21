import sqlite3, json, datetime

conn = sqlite3.connect(r'C:\Users\cyber\.local\share\mimocode\mimocode.db')
c = conn.cursor()

# Debug: check message data structure
print("=" * 80)
print("DEBUG: Message data structure from Salesforce session")
print("=" * 80)
c.execute("""
    SELECT m.id, m.data, m.agent_id, m.time_created
    FROM message m
    WHERE m.session_id = 'ses_083e78d42ffezgDFE7OAUl6CSq'
    ORDER BY m.time_created ASC
    LIMIT 10
""")
for r in c.fetchall():
    try:
        d = json.loads(r[1])
        role = d.get('role', 'N/A')
        content = str(d.get('content', ''))[:200]
        agent = r[2] or 'main'
        print(f"  id={r[0][:20]} role={role} agent={agent}")
        print(f"    keys: {list(d.keys())}")
        print(f"    content preview: {content}")
        print()
    except Exception as e:
        print(f"  Error: {e}")
        print(f"  Raw data: {r[1][:200]}")
        print()

# Check if user messages use a different structure
print("=" * 80)
print("ALL ROLES in Salesforce session")
print("=" * 80)
c.execute("""
    SELECT json_extract(m.data, '$.role'), COUNT(*)
    FROM message m
    WHERE m.session_id = 'ses_083e78d42ffezgDFE7OAUl6CSq'
    GROUP BY json_extract(m.data, '$.role')
""")
for r in c.fetchall():
    print(f"  {r[0]}: {r[1]} messages")

# Try a different path for content
print("\n" + "=" * 80)
print("USER MESSAGES - alternative path check")
print("=" * 80)
c.execute("""
    SELECT m.id, m.data
    FROM message m
    WHERE m.session_id = 'ses_083e78d42ffezgDFE7OAUl6CSq'
      AND json_extract(m.data, '$.role') = 'user'
    ORDER BY m.time_created ASC
    LIMIT 5
""")
for r in c.fetchall():
    d = json.loads(r[1])
    print(f"  id={r[0][:20]}")
    print(f"  full keys: {list(d.keys())}")
    # Check all possible content paths
    for key in ['content', 'text', 'message', 'input', 'query', 'prompt']:
        if key in d:
            print(f"    {key}: {str(d[key])[:200]}")
    print(f"    full data: {r[1][:300]}")
    print()

# Get user messages with content from jarvis-personal-os sessions
print("=" * 80)
print("JARVIS SESSIONS - USER MESSAGES")
print("=" * 80)
c.execute("""
    SELECT s.id, s.title, m.time_created, m.data
    FROM message m
    JOIN session s ON s.id = m.session_id
    WHERE json_extract(m.data, '$.role') = 'user'
      AND (s.directory LIKE '%jarvis%' OR s.directory LIKE '%antigravity%')
    ORDER BY m.time_created DESC
    LIMIT 20
""")
for r in c.fetchall():
    ts = datetime.datetime.fromtimestamp(r[2]/1000).strftime('%Y-%m-%d %H:%M')
    d = json.loads(r[3])
    content = ''
    for key in ['content', 'text', 'message', 'input', 'query', 'prompt']:
        if key in d:
            content = str(d[key])[:250]
            break
    if not content:
        content = r[3][:250]
    print(f"  [{ts}] [{r[0][:20]}] {content}")
    print()

conn.close()
