import srp

#client
usr= srp.User( 'testuser', 'testpassword' )
uname, A = usr.start_authentication()

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

#server -> client : HAMK
usr.verify_session(HAMK)


print(usr.authenticated())
print(svr.authenticated())
