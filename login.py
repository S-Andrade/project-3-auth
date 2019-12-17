import srp
import csv

#client
usr= srp.User( 'testuser', 'testpassword' )
uname, A = usr.start_authentication()
print(A)
#client -> Server : username,A

#server
#vai boscar ao ficheiro o username e a password
salt, vkey = srp.create_salted_verification_key( 'testuser', 'testpassword' )
svr = srp.Verifier( uname, salt, vkey, A)
s,B = svr.get_challenge()

#sever -> client: s,B

#client
M = usr.process_challenge(s, B)

#client -> server : M

#server
HAMK = svr.verify_session(M)
print(HAMK)

#client
t = usr.verify_session(HAMK)
print(t)

print(svr.authenticated())
print(usr.authenticated())

def getPassword(uname):
    filepath = 'login.txt'
    with open(filepath) as fp:
        for line in fp:
            l = line.split()
            if l[0] == uname:
                return l[1]
    return None


p = getPassword('testuser')
print(p)
