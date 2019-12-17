from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import datetime
import PyKCS11
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

#criar certificado do servidor
key = rsa.generate_private_key(public_exponent=65537,key_size=2048,backend=default_backend())

subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"mysite.com")
    ])

cert = x509.CertificateBuilder().subject_name(
        subject
        ).issuer_name(
                issuer
                ).public_key(
                        key.public_key()
                        ).serial_number(x509.random_serial_number()
                                ).not_valid_before(
                                        datetime.datetime.utcnow()
                                        ).not_valid_after(
                                                datetime.datetime.utcnow() + datetime.timedelta(days=10)
                                                ).add_extension(
                                                        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),critical=False,
                                                        ).sign(key, hashes.SHA256(), default_backend())



print(cert)



#assinar um texto com o certificado do servidor
message = b"A message I want to sign"
signature = key.sign(message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
            ),
        hashes.SHA256()
        )

print(signature)


#cliente verifica

public_key = cert.public_key()
public_key.verify(signature,message,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())


text = cert.message()
print(text)
