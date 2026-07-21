import sqlite3, json, datetime

conn = sqlite3.connect(r'C:\Users\cyber\.local\share\mimocode\mimocode.db')
c = conn.cursor()

# 1. Get session ses_083e78d42ffezgDFE7OAUl6CSq (the main Salesforce project session) - user messages
print("=" * 80)
print("SES_083E USER MESSAGES (Salesforce Security Framework)")
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
    content = (r[0] or '')[:300]
    if content.strip():
        print(f"  [{ts}] {content}")
        print()

# 2. Check for the jarvis-personal-os sessions
print("=" * 80)
print("JARVIS PERSONAL OS SESSIONS")
print("=" * 80)
c.execute("""
    SELECT s.id, s.title, s.time_created
    FROM session s
    WHERE s.directory LIKE '%jarvis%'
       OR s.directory LIKE '%antigravity%'
       OR s.title LIKE '%Jarvis%'
       OR s.title LIKE '%Voice%'
       OR s.title LIKE '%Browser%'
       OR s.title LIKE '%Travel%'
       OR s.title like '%Phase%'
    ORDER BY s.time_created DESC
    LIMIT 20
""")
for r in c.fetchall():
    ts = datetime.datetime.fromtimestamp(r[2]/1000).strftime('%Y-%m-%d %H:%M')
    print(f"  {r[0]} | {ts} | {r[1][:80]}")

# 3. Get all distinct session projects/directories
print("\n" + "=" * 80)
print("ALL DISTINCT SESSION DIRECTORIES")
print("=" * 80)
c.execute("""
    SELECT directory, COUNT(*) as cnt, MIN(time_created) as first, MAX(time_created) as last
    FROM session
    WHERE directory IS NOT NULL
    GROUP BY directory
    ORDER BY last DESC
""")
for r in c.fetchall():
    first = datetime.datetime.fromtimestamp(r[2]/1000).strftime('%Y-%m-%d')
    last = datetime.datetime.fromtimestamp(r[3]/1000).strftime('%Y-%m-%d')
    print(f"  {r[1]:3d} sessions | {first} to {last} | {r[0]}")

# 4. Check if there's a notes.md for any session
print("\n" + "=" * 80)
print("SESSIONS WITH notes.md or progress.md")
print("=" * 80)
c.execute("""
    SELECT DISTINCT s.id, s.title
    FROM session s
    JOIN part p ON p.session_id = s.id
    WHERE json_extract(p.data, '$.tool') IN ('write', 'edit')
      AND json_extract(p.data, '$.type') = 'tool'
    ORDER BY s.time_created DESC
    LIMIT 15
""")
for r in c.fetchall():
    print(f"  {r[0]} | {r[1][:60]}")

# 5. Check total message counts per session
print("\n" + "=" * 80)
print("MESSAGE COUNTS PER REAL SESSION")
print("=" * 80)
c.execute("""
    SELECT s.id, s.title, s.time_created,
           (SELECT COUNT(*) FROM message m WHERE m.session_id = s.id AND json_extract(m.data, '$.role') = 'user') as user_msgs,
           (SELECT COUNT(*) FROM message m WHERE m.session_id = s.id AND json_extract(m.data, '$.role') = 'assistant') as assistant_msgs
    FROM session s
    WHERE s.title NOT LIKE 'checkpoint-writer%'
    ORDER BY s.time_created DESC
    LIMIT 15
""")
for r in c.fetchall():
    ts = datetime.datetime.fromtimestamp(r[2]/1000).strftime('%Y-%m-%d %H:%M')
    print(f"  {r[0]} | {ts} | user={r[3]:3d} assistant={r[4]:3d} | {r[1][:60]}")

conn.close()
