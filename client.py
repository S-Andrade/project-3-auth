import asyncio
import json
import argparse
import coloredlogs, logging
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from salsa20 import XSalsa20_xor




logger = logging.getLogger('root')

STATE_CONNECT = 0
STATE_OPEN = 1
STATE_DATA = 2
STATE_CLOSE = 3


class ClientProtocol(asyncio.Protocol):
    """
    Client that handles a single client
    """

    def __init__(self, file_name, loop):
        """
        Default constructor
        :param file_name: Name of the file to send
        :param loop: Asyncio Loop to use
        """

        self.file_name = file_name
        self.loop = loop
        self.state = STATE_CONNECT  # Initial State
        self.buffer = ''  # Buffer to receive data chunks
        self.algorithms = []
        self.server_public_key = ''
        self.key = ''
        self.encryptkey = ''
        self.file_name_encrypted = 'clientFiles/file_encrypted.txt'
        self.iv = ''
        self.cert_server=''
        self.sign_server=''
        self.text_server = ''
        self.text_to_sign = ''
        self.cert_client = ''
        self.sign_client = ''
        self.s =''
        self.B = ''
        self.usr =''

    def connection_made(self, transport) -> None:
        """
        Called when the client connects.

        :param transport: The transport stream to use for this client
        :return: No return
        """
        self.transport = transport

        logger.debug('Connected to Server')
        self.text_server = b"prova que és o servidor"
        self._send({'type': 'HEY', 'data': self.text_server})
        


        #message = {'type': 'OPEN', 'file_name': self.file_name}
        #self._send(message)

        self.state = STATE_OPEN


    def data_received(self, data: str) -> None:
        """
        Called when data is received from the server.
        Stores the data in the buffer

        :param data: The data that was received. This may not be a complete JSON message
        :return:
        """
        logger.debug('Received: {}'.format(data))
        try:
            self.buffer += data.decode()
        except:
            logger.exception('Could not decode data from client')

        idx = self.buffer.find('\r\n')

        while idx >= 0:  # While there are separators
            frame = self.buffer[:idx + 2].strip()  # Extract the JSON object
            self.buffer = self.buffer[idx + 2:]  # Removes the JSON object from the buffer

            self.on_frame(frame)  # Process the frame
            idx = self.buffer.find('\r\n')

        if len(self.buffer) > 4096 * 1024 * 1024:  # If buffer is larger than 4M
            logger.warning('Buffer to large')
            self.buffer = ''
            self.transport.close()

    def on_frame(self, frame: str) -> None:
        """
        Processes a frame (JSON Object)

        :param frame: The JSON Object to process
        :return:
        """

        #logger.debug("Frame: {}".format(frame))
        try:
            message = json.loads(frame)
        except:
            logger.exception("Could not decode the JSON message")
            self.transport.close()
            return

        mtype = message.get('type', None)
        if mtype == 'CERT_SERVER':
            self.cert_server = base64.b64decode(message.get('data')).encode()
        if mtype == 'SIGN_SERVER':
            self.sign_server = base64.b64decode(message.get('data')).encode()
            if not self.verifyServer():
                return
            self.text_to_sign = b"eu sou quem digo ser"
            self._send({'type': 'SERVER_OK', 'data': self.text_to_sign})
            self.getCC()
            self._send({'type': 'CERT_CLIENT', 'data': base64.b16encode(self.cert_client).decode()})
            self._send({'type': 'SIGN_CLIENT', 'data': base64.b16encode(self.sign_client).decode()})

        if mtype == 'START_LOGIN':
            self.usr = srp.User('testuser', 'testpassword')
            uname, A = self.usr.start_authentication()
            self._send({'type': 'USER', 'uname' : uname, base64.b16encode(A).decode()})

        if mtype =='s':
            self.s = base64.b64decode(message.get('data')).encode()
        if mtype =='B':
            self.B = base64.b64decode(message.get('data')).encode()
            M = self.usr.process_challenge(self.s, self.B)
            self._send({'type', 'M', 'data', base64.b64encode(M).decode()})

        if mtype == 'OKOK':
            input = 'Salsa20_SHA256'
            self.algorithms = input.split('_')
            message = {'type': 'HELLO', 'data': input }
            logger.info("Hello")
            self._send(message)

        if mtype == 'PUBLIC_KEY':
            pem_public_key = base64.b64decode(message.get('data'))
            self.server_public_key = serialization.load_pem_public_key(
                pem_public_key,
                backend=default_backend()
            )
            self.encryptkey = self.getEncriptKey()
            logger.info("Send key")
            self._send({'type': 'SECURE', 'data': base64.b64encode(self.encryptkey).decode()})

            if 'AES' in self.algorithms:
                self.iv = os.urandom(16)
            if 'Salsa20' in self.algorithms:
                self.iv = os.urandom(24)
            logger.info("Send iv")
            self._send({'type': 'SECURE_IV', 'data': base64.b64encode(self.iv).decode()})
            self.encryptFile()
            message = {'type': 'OPEN', 'file_name': self.file_name_encrypted}
            self._send(message)
            self.send_file(self.file_name_encrypted)

        if mtype == 'OK':  # Server replied OK. We can advance the state
            if self.state == STATE_OPEN:
                logger.info("Channel open")
                self.send_file(self.file_name)
            elif self.state == STATE_DATA:  # Got an OK during a message transfer.
                # Reserved for future use
                pass
            else:
                logger.warning("Ignoring message from server")
            return

        elif mtype == 'ERROR':
            logger.warning("Got error from server: {}".format(message.get('data', None)))
        else:
            logger.warning("Invalid message type")

        self.transport.close()
        self.loop.stop()

    def connection_lost(self, exc):
        """
        Connection was lost for some reason.
        :param exc:
        :return:
        """
        logger.info('The server closed the connection')
        self.loop.stop()

    def send_file(self, file_name: str) -> None:
        """
        Sends a file to the server.
        The file is read in chunks, encoded to Base64 and sent as part of a DATA JSON message
        :param file_name: File to send
        :return:  None
        """

        with open(file_name, 'rb') as f:
            message = {'type': 'DATA', 'data': None}
            read_size = 16 * 60
            while True:
                data = f.read(16 * 60)
                message['data'] = base64.b64encode(data).decode()
                self._send(message)

                if len(data) != read_size:
                    break

            self._send({'type': 'CLOSE'})
            logger.info("File transferred. Closing transport")
            self.transport.close()

    def _send(self, message: str) -> None:
        """
        Effectively encodes and sends a message
        :param message:
        :return:
        """
        logger.debug("Send: {}".format(message))

        message_b = (json.dumps(message) + '\r\n').encode()
        self.transport.write(message_b)

    def getEncriptKey(self):
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        self.key = kdf.derive(salt)

        if 'SHA256' in self.algorithms:
            encrypted = self.server_public_key.encrypt(
                self.key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        elif 'SHA512' in self.algorithms:
            encrypted = self.server_public_key.encrypt(
                self.key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA512()),
                    algorithm=hashes.SHA512(),
                    label=None
                )
            )
        else:
            logger.warning("Invalid algorithm")

        return encrypted

    def encryptFile(self):
        with open(self.file_name, 'r') as file:
            text = file.read()
        text = str.encode(text)
        if "AES" in self.algorithms:
            algorithm_name = algorithms.AES(self.key)
            if "CBC" in  self.algorithms:
                bs = int(algorithm_name.block_size / 8)
                missing_bytes = bs - (len(text) % bs)
                if missing_bytes == 0:
                    missing_bytes = bs
                padding = bytes([missing_bytes] * missing_bytes)
                text += padding
                cipher = Cipher(algorithm_name, modes.CBC(self.iv), backend=default_backend())
                encryptor = cipher.encryptor()
                end = encryptor.update(text) + encryptor.finalize()
            elif "GCM" in self.algorithms:
                aad = str.encode(''.join(self.algorithms))
                aesgcm = AESGCM(self.key)
                end = aesgcm.encrypt(self.iv, text, aad)
            else:
                raise (Exception("Invalid mode"))

        elif "Salsa20" in self.algorithms:
            end = XSalsa20_xor(text, self.iv, self.key)

        else:
            raise (Exception("Invalid algorithm"))

        with open(self.file_name_encrypted, 'wb') as file:
            file.write(end)

    def verifyServer(self):
        public_key = self.cert_server.public_key()
        v = public_key.verify(self.sign_server,self.text_server,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
        if v == None:
            return True
        else:
            return False

    def getCC(self):
        lib = '/usr/local/lib/libpteidpkcs11.so'
        pkcs11 = PyKCS11.PyKCS11Lib()
        pkcs11.load(lib)
        slots = pkcs11.getSlotList()

        certificate = None
        for slot in slots:
            # print(pkcs11.getTokenInfo(slot))
            all_attr = list(PyKCS11.CKA.keys())
            # Filter attributes
            all_attr = [e for e in all_attr if isinstance(e, int)]
            # print(all_attr)
            session = pkcs11.openSession(slot)
            for obj in session.findObjects():
                # Get object attributes
                attr = session.getAttributeValue(obj, all_attr)
                # Create dictionary with attributes
                attr = dict(zip(map(PyKCS11.CKA.get, all_attr), attr))
                print('Label:', str(attr['CKA_LABEL']))
                if str(attr['CKA_LABEL']) == "b'CITIZEN AUTHENTICATION CERTIFICATE'":
                    try:
                        self.cert_client = x509.load_der_x509_certificate(bytes(attr['CKA_VALUE']), default_backend())
                    except:
                        print("Something else went wrong")

            private_key = session.findObjects(
                [(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY), (PyKCS11.CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')])[0]
            mechanism = PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS, None)
            text = b'text to sign'
            self.sign_client = bytes(session.sign(private_key, self.text_to_sign, mechanism))

def main():
    parser = argparse.ArgumentParser(description='Sends files to servers.')
    parser.add_argument('-v', action='count', dest='verbose',
                        help='Shows debug messages',
                        default=0)
    parser.add_argument('-s', type=str, nargs=1, dest='server', default='127.0.0.1',
                        help='Server address (default=127.0.0.1)')
    parser.add_argument('-p', type=int, nargs=1,
                        dest='port', default=5000,
                        help='Server port (default=5000)')

    parser.add_argument(type=str, dest='file_name', help='File to send')

    args = parser.parse_args()
    file_name = os.path.abspath(args.file_name)
    level = logging.DEBUG if args.verbose > 0 else logging.INFO
    port = args.port
    server = args.server

    coloredlogs.install(level)
    logger.setLevel(level)

    logger.info("Sending file: {} to {}:{} LogLevel: {}".format(file_name, server, port, level))

    loop = asyncio.get_event_loop()
    coro = loop.create_connection(lambda: ClientProtocol(file_name, loop),
                                  server, port)
    loop.run_until_complete(coro)
    loop.run_forever()
    loop.close()

if __name__ == '__main__':
    main()
