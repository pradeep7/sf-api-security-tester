import sqlite3, json, datetime

conn = sqlite3.connect(r'C:\Users\cyber\.local\share\mimocode\mimocode.db')
c = conn.cursor()

# 1. List real sessions (non-subagent, non-checkpoint-writer) for global project
print("=" * 80)
print("RECENT SESSIONS (global project)")
print("=" * 80)
c.execute("""
    SELECT id, title, time_created
    FROM session
    WHERE project_id = 'global'
      AND title NOT LIKE 'checkpoint-writer%'
    ORDER BY time_created DESC
    LIMIT 25
""")
for r in c.fetchall():
    ts = datetime.datetime.fromtimestamp(r[2]/1000).strftime('%Y-%m-%d %H:%M')
    print(f"  {r[0]} | {ts} | {r[1][:80]}")

# 2. Search user messages for durable keywords
print("\n" + "=" * 80)
print("USER STATEMENTS WITH DURABLE KEYWORDS")
print("=" * 80)
keywords = ['always', 'never', 'remember', 'must', 'rule', 'decision', 'should not', 'always use', 'do not', 'always use']
seen = set()
for kw in keywords:
    c.execute("""
        SELECT m.session_id, json_extract(m.data, '$.content')
        FROM message m
        WHERE json_extract(m.data, '$.role') = 'user'
          AND json_extract(m.data, '$.content') LIKE ?
        ORDER BY m.time_created DESC
        LIMIT 5
    """, (f'%{kw}%',))
    for r in c.fetchall():
        key = (r[0], (r[1] or '')[:100])
        if key not in seen:
            seen.add(key)
            content = (r[1] or '')[:250]
            print(f"  [{kw}] [{r[0][:20]}] {content}")
    print()

# 3. Search for errors and fixes in assistant messages
print("=" * 80)
print("RECENT ERROR PATTERNS IN TRAJECTORY")
print("=" * 80)
c.execute("""
    SELECT m.session_id, json_extract(m.data, '$.role'), json_extract(p.data, '$.type'), substr(json_extract(p.data, '$.text'), 1, 300)
    FROM message m
    JOIN part p ON p.message_id = m.id
    WHERE json_extract(p.data, '$.type') = 'tool'
      AND json_extract(p.data, '$.tool') = 'bash'
      AND json_extract(p.data, '$.state.output') LIKE '%Error%'
    ORDER BY m.time_created DESC
    LIMIT 10
""")
for r in c.fetchall():
    ts_note = f"[{r[0][:20]}]"
    print(f"  {ts_note} {str(r[3])[:200]}")

# 4. Search for config/file modifications in trajectory
print("\n" + "=" * 80)
print("WRITE/EDIT OPERATIONS IN TRAJECTORY")
print("=" * 80)
c.execute("""
    SELECT m.session_id, json_extract(p.data, '$.tool'), substr(json_extract(p.data, '$.state.input'), 1, 200)
    FROM message m
    JOIN part p ON p.message_id = m.id
    WHERE json_extract(p.data, '$.type') = 'tool'
      AND json_extract(p.data, '$.tool') IN ('write', 'edit')
    ORDER BY m.time_created DESC
    LIMIT 15
""")
for r in c.fetchall():
    print(f"  [{r[0][:20]}] {r[1]}: {str(r[2])[:180]}")

conn.close()
