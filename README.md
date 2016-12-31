# dnarc

### Introduction

This is a Python Flask application that implements a basic distributed record store. The records are in JSON format, stored in SQLite and are signed using ed25519 signatures. Resource claims can be synced between instances very quickly over HTTP, either push or pull, and existing records can only be signed using the same authentication key.

### Interface

The HTTP interface exposes the following methods:

##### List all sync domains
```
GET /domains HTTP/1.1
```
##### List all claims
```
GET /claims HTTP/1.1
```
##### Search for "label" in domain "com.domain"
```
GET /claims/com.domain/label HTTP/1.1
```
##### Search for all claims in domain "com.domain"
```
GET /claims/com.domain HTTP/1.1
```
##### Register a single claim with signature "signature"
```
PUT /claims/signature
{
  "domain": "com.domain",
  "label": "abc",
  "signedby": "publickey"
  "timestamp": 1483206065,
  "key1": "value1",
  "key2": ["value3", "value4", ...],
  ...
}
```
