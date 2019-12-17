from datetime import datetime
import sys
import PyKCS11
import binascii
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

lib = '/usr/local/lib/libpteidpkcs11.so'
pkcs11 = PyKCS11.PyKCS11Lib()
pkcs11.load(lib)
slots = pkcs11.getSlotList()

certificate = None
for slot in slots:
    #print(pkcs11.getTokenInfo(slot))
    all_attr = list(PyKCS11.CKA.keys())
    #Filter attributes
    all_attr = [e for e in all_attr if isinstance(e, int)]
    #print(all_attr)
    session = pkcs11.openSession(slot)
    for obj in session.findObjects():
        # Get object attributes
        attr = session.getAttributeValue(obj, all_attr)
        # Create dictionary with attributes
        attr = dict(zip(map(PyKCS11.CKA.get, all_attr), attr))
        print('Label:', str(attr['CKA_LABEL']))
        if str(attr['CKA_LABEL']) == "b'CITIZEN AUTHENTICATION CERTIFICATE'":
            try:
                certificate = x509.load_der_x509_certificate(bytes(attr['CKA_VALUE']),default_backend())
            except:
                print("Something else went wrong")

    private_key = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),(PyKCS11.CKA_LABEL,'CITIZEN AUTHENTICATION KEY')])[0]
    mechanism = PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS, None)
    text = b'text to sign'
    signature = bytes(session.sign(private_key, text, mechanism))
    



print(signature)
print(text)
public_key = certificate.public_key()
public_key.verify(signature,text,padding.PKCS1v15(),hashes.SHA1())


