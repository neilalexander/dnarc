# dnarc

### Introduction

This is a Python Flask application that implements a basic distributed record store. The records are in JSON format, stored in SQLite and are signed using ed25519 signatures. Resource claims can be synced between instances very quickly over HTTP, either push or pull, and existing records can only be signed using the same authentication key.

### Interface

The HTTP interface exposes the following methods:

##### List all sync domains
```
GET /domains HTTP/1.1
```
Returns a JSON list of all supported sync domains.
##### List all claims
```
GET /claims HTTP/1.1
```
Returns a JSON dict of all claims known to this node, regardless of sync domain.
##### Search for "label" in domain "com.domain"
```
GET /claims/com.domain/label HTTP/1.1
```
Returns a JSON dict of the specific claim under "label" within the sync domain "com.domain".
##### Search for all claims in domain "com.domain"
```
GET /claims/com.domain HTTP/1.1
```
Returns a JSON dict of all claims within the sync domain "com.domain".
##### Register a single claim with signature "signature"
```
PUT /claims/signature HTTP/1.1
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
Returns a JSON dict indicating success/failure by signature.

### Syncing

Define some peers in the 'peers' SQLite table and whether or not they are a "push" or a "pull" peer. Updates are sent to "push" peers based on the last successful record timestamp pushed. Updates from "pull" peers are based on the most recent known timestamp within the sync domain. 

In theory a "push" or "pull" can be initiated at any time, i.e. an application can make a ```/sync/push``` call to immediately push new records to known peers. 

If a previous record of the same label is found, the public key in the "signedby" attribute of the previous record is used to verify the signature of the new record. If successfully verified then the record is signed using the same key and the update is allowed.

If the public key does not match the "signedby" attribute then it is next checked against the "newowner" key in the record, an optional parameter which can be used to transfer the record ownership to a new public key. 

A node, when receiving new updates either by push or pull, should replay through the history from oldest to newest. Whether all nodes needs to keep all of that history is down to implementation detail, but keeping an entire history allows all record ownership changes etc to be fully tracked. 

Right now there is not much of a mechanism for resolving merge conflicts where a given label was assigned on two hosts, this requires some work.
