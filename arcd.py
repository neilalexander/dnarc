#!/usr/bin/python

import sys
import json
import nacl.signing
import sqlite3
import binascii
import struct
import requests

import arc

from flask import Flask, Response, request
app = Flask(__name__)

db = sqlite3.connect("claims.db", check_same_thread=False)
db.row_factory = sqlite3.Row

@app.route("/domains", methods=['GET'])
def getClaimDomains():
    dbc = db.cursor()
    dbc.execute("SELECT * FROM domains")
    def respond():
        r = {"get": {"type": "domains"}, "results": []}
        for row in dbc.fetchall():
            r['results'].append(row[0])
        return json.dumps(r, sort_keys=True, indent=4)
    return Response(respond(), mimetype='application/json')

@app.route("/claims", methods=['GET'])
def getClaims():
    dbc = db.cursor()
    dbc.execute("SELECT * FROM claims "
                "GROUP BY domain, label ORDER BY timestamp ASC")

    def respond():
        r = {"get": {"type": "claims"}, "results": {}}
        for row in dbc.fetchall():
            r['results'][row['signature']] = json.loads(row['payload'])
        return json.dumps(r, sort_keys=True, indent=4)
    return Response(respond(), mimetype='application/json')

@app.route("/claims/<string:domain>/<string:label>", methods=['GET'])
def getClaimByDomainLabel(domain, label):
    dbc = db.cursor()
    dbc.execute("SELECT * FROM claims WHERE domain=? AND label=?"
                "GROUP BY domain, label ORDER BY timestamp ASC", [domain, label])

    def respond():
        r = {"get": {"type": "claims", "domain": domain, "label": label},
             "results": {}}
        for row in dbc.fetchall():
            r['results'][row['signature']] = json.loads(row['payload'])
        return json.dumps(r, sort_keys=True, indent=4)
    return Response(respond(), mimetype='application/json')

@app.route("/claims/<string:domain>", methods=['GET'])
def getClaimByDomain(domain):
    dbc = db.cursor()
    dbc.execute("SELECT * FROM claims WHERE domain=?"
                "GROUP BY domain, label ORDER BY timestamp ASC", [domain])

    def respond():
        r = {"criteria": {"type": "claims", "domain": domain},
             "results": {}}
        for row in dbc.fetchall():
            r['results'][row['signature']] = json.loads(row['payload'])
        return json.dumps(r, sort_keys=True, indent=4)
    return Response(respond(), mimetype='application/json')

@app.route("/claims/<string:signature>", methods=['PUT'])
def registerClaim(signature):
    return registerClaim(signature, request.get_json())

def registerClaim(signature, newRecord):
    newRecordJSON = json.loads(newRecord)
    signature = binascii.unhexlify(signature)

    try:
        assert 'domain' in newRecordJSON, 'domain'
        assert 'label' in newRecordJSON, 'label'
        assert 'signedby' in newRecordJSON, 'signedby'
        assert 'timestamp' in newRecordJSON, 'timestamp'
    except AssertionError as e:
        r = {"error": "Invalid request, a required key is missing: " + e.args[0]}
        return Response(json.dumps(r, sort_keys=True, indent=4), mimetype='application/json'), 400

    dbc = db.cursor()
    dbc.execute(
        "SELECT payload, signature FROM claims WHERE domain=? AND label=?"
        "ORDER BY timestamp DESC",
        [newRecordJSON['domain'], newRecordJSON['label']])

    authorised = True

    try: previousRecord = json.loads(dbc.fetchone()[0])
    except: previousRecord = False

    if previousRecord != False:
        if 'newowner' in previousRecord:
            authorised &= arc.verifyClaimSignature(newRecord, signature, previousRecord['newowner'])
        if 'signedby' in previousRecord:
            authorised &= arc.verifyClaimSignature(newRecord, signature, previousRecord['signedby'])

    if not authorised:
        r = {"error": "Not authorised, signature does not match previous record"}
        return Response(json.dumps(r), mimetype='application/json'), 401

    try:
        dbc.execute(
            "INSERT INTO claims VALUES (?, ?, ?, ?, ?)",
            [newRecordJSON['domain'], newRecordJSON['label'], newRecordJSON['timestamp'],
             binascii.hexlify(signature), newRecord])
        db.commit()
    except sqlite3.IntegrityError:
        pass

    def respond():
        r = {"saved": [newRecordJSON['signedby']]}
        return json.dumps(r, sort_keys=True, indent=4)
    return Response(respond(), mimetype='application/json'), 200

@app.route("/sync/<string:domain>/<int:timestamp>", methods=['GET'])
def getSyncDomain(domain, timestamp):
    dbc = db.cursor()
    dbc.execute("SELECT * FROM claims WHERE domain=? AND timestamp>?"
                "ORDER BY timestamp ASC", [domain, timestamp])

    def respond():
        r = {"get": {"type": "sync", "domain": domain}, "results": {}}
        for row in dbc.fetchall():
            r['results'][row['signature']] = row['payload']
        return json.dumps(r, sort_keys=True, indent=4)
    return Response(respond(), mimetype='application/json')

@app.route("/sync/pull", methods=['GET'])
def syncPullServers():
    dbc = db.cursor()
    dbc.execute("SELECT timestamp FROM claims "
                "ORDER BY timestamp DESC LIMIT 1")
    mostRecentRecordTimestamp = dbc.fetchone()[0]
    dbc.execute("SELECT * FROM peers WHERE mode='pull'")
    r = {"saved": [], "rejected": []}

    for row in dbc.fetchall():
        requestURL = row['url'].rstrip("/") + '/sync/' + row['domain'] + \
                     '/' + str(mostRecentRecordTimestamp)
        receivedJSON = requests.get(requestURL).json()

        for receivedSignature, receivedRecord in receivedJSON['results'].items():
            registerResponse = registerClaim(receivedSignature, receivedRecord)

            if registerResponse[1] == 200:
                receivedRecordJSON = json.loads(receivedRecord)
                db.execute("UPDATE peers SET lastsyncedtimestamp=? WHERE "
                   "url=? AND domain=? AND mode='pull' AND lastsyncedtimestamp<?",
                   [receivedRecordJSON['timestamp'], row['url'],
                    row['domain'], receivedRecordJSON['timestamp']])
                r['saved'].append(receivedSignature)
            else:
                r['rejected'].append(receivedSignature)
                break

    return Response(json.dumps(r, sort_keys=True, indent=4), mimetype='application/json'), 200

@app.route("/sync/push", methods=['GET'])
def syncPushServersGet():
    dbc = db.cursor()
    dbc.execute("SELECT * FROM peers WHERE mode='push'")
    r = {"presync": {}, "postsync": {}}
    s = {}

    for row in dbc.fetchall():
        dburl = row['url']
        dbdomain = row['domain']
        url = dburl.rstrip("/") + "/sync/push/" + dbdomain
        dbc.execute("SELECT lastsyncedtimestamp FROM peers WHERE "
                    "domain=? AND url=? AND MODE='push' "
                    "ORDER BY lastsyncedtimestamp ASC LIMIT 1",
                    [row['domain'], row['url']])
        oldestRecordTimestamp = int(dbc.fetchone()[0])
        r['presync'][url] = oldestRecordTimestamp

        dbc.execute("SELECT * FROM claims WHERE domain=? AND timestamp>=?",
                    [row['domain'], oldestRecordTimestamp])

        for srow in dbc.fetchall():
            selectedJSON = json.loads(srow['payload'])
            s[srow['signature']] = selectedJSON

        receivedJSON = requests.post(url, json=s).json()
        r['postsync'][url] = receivedJSON['acceptedTimestamp']

        db.execute("UPDATE peers SET lastsyncedtimestamp=? WHERE "
                   "url=? AND domain=? AND mode='push'",
                   [receivedJSON['acceptedTimestamp'], dburl, dbdomain])
        db.commit()
    return Response(json.dumps(r, sort_keys=True, indent=4), mimetype='application/json'), 200

@app.route("/sync/push/<string:domain>", methods=['POST'])
def syncPushServersPost(domain):
    newRecordsJSON = request.get_json()
    r = {"acceptedTimestamp": 0, "saved": [], "rejected": []}

    for signature, newRecord in newRecordsJSON.items():
        registerResponse = registerClaim(signature, json.dumps(newRecord))

        if registerResponse[1] == 200:
            r['saved'].append(signature)

            if newRecord['timestamp'] > r['acceptedTimestamp']:
                r['acceptedTimestamp'] = newRecord['timestamp']
        else:
            break

    return Response(json.dumps(r), mimetype='application/json'), 200

if __name__ == "__main__":
    db.execute("CREATE TABLE IF NOT EXISTS domains (domain, PRIMARY KEY(domain))")
    db.execute("INSERT OR REPLACE INTO domains VALUES('net.dn42.registry')")
    db.execute("CREATE TABLE IF NOT EXISTS claims (domain, label, timestamp, signature, " \
               "payload, PRIMARY KEY(domain, label, signature), " \
               "FOREIGN KEY(domain) REFERENCES domains(domain))")
    db.execute("CREATE TABLE IF NOT EXISTS peers (domain, url, mode, lastsyncedtimestamp, "\
               "PRIMARY KEY(domain, url, mode))")
    db.commit()
    app.run(threaded=True, host='0.0.0.0')
