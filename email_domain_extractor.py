import sqlite3

conn = sqlite3.connect('Email_Domain_Db.sqlite')
cur = conn.cursor()

cur.execute('DROP TABLE IF EXISTS Counts')
cur.execute('CREATE TABLE Counts(Email_Domain TEXT, Count INTEGER)')

fname = input ('Enter filename: ')
fh = open(fname)
for line in fh:
    if not line.startswith('From: '): continue
    pieces = line.split()
    domain = pieces[1].split('@')[1]
    cur.execute('SELECT * FROM Counts WHERE Email_Domain = ? ', (domain,))
    row = cur.fetchone()
    if row is None:
        cur.execute('INSERT INTO Counts (Email_Domain, count) VALUES (?, 1)', (domain,))
    else:
        cur.execute('UPDATE Counts SET count = count+1 WHERE Email_Domain = ?', (domain,))
    conn.commit()

sqlstr = '''SELECT * FROM Counts
            ORDER BY count DESC
            LIMIT 5'''
for row in cur.execute(sqlstr):
    print(str(row[0]), row[1])

cur.close()
