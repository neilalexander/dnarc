import json
import calendar, time
import requests
import nacl.signing
import binascii
import pprint

pp = pprint.PrettyPrinter()

def verifyClaimSignature(claim, sig, publickey):
    try:
        vkey = nacl.signing.VerifyKey(publickey, encoder=nacl.encoding.HexEncoder)
        vkey.verify(sig + claim.encode('utf-8'))
        return True
    except:
        return False

if __name__ == "__main__":
    try: pkf = open("private.key", "r+")
    except IOError: pkf = open("private.key", "w+")

    try:
        print "Loading existing signing key"
        skey = nacl.signing.SigningKey(pkf.read(32), encoder=nacl.encoding.RawEncoder)
    except ValueError:
        print "Generating new signing key"
        skey = nacl.signing.SigningKey.generate()
        pkf.write(skey.encode(encoder=nacl.encoding.RawEncoder))

    pkf.close()
    vkey = skey.verify_key

    print "Signing key: " + skey.encode(encoder=nacl.encoding.HexEncoder)
    print "Verify key: " + vkey.encode(encoder=nacl.encoding.HexEncoder)

    newClaim = '''
    {
        "domain": "net.dn42.registry",
        "label": "domain:lynx.dn42",
        "nameservers": {
            "ns.lynx.dn42": "172.22.97.1"
        }
    }
    '''

    j = json.loads(newClaim)
    j['timestamp'] = calendar.timegm(time.gmtime());
    j['signedby'] = skey.verify_key.encode(encoder=nacl.encoding.HexEncoder)
    j = json.dumps(j)

    sig = skey.sign(j)

    res = requests.put('http://localhost:5000/claims/' + binascii.hexlify(sig.signature), json=j)
    print res.json()
