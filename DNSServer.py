import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.rdtypes.ANY
from dns.rdtypes.ANY.MX import MX
from dns.rdtypes.ANY.SOA import SOA
import socket
import threading
import signal
import os
import sys
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
from cryptography.hazmat.backends import default_backend

def generate_aes_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt_with_aes(input_string: str, password: str, salt: bytes) -> bytes:
    key = generate_aes_key(password, salt)
    fernet = Fernet(key)
    return fernet.encrypt(input_string.encode())

def decrypt_with_aes(encrypted_data: bytes, password: str, salt: bytes) -> str:
    key = generate_aes_key(password, salt)
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_data).decode()

salt = b'Tandon'
password = 'dsc471@nyu.edu'
input_string = 'AlwaysWatching'

encrypted_value = encrypt_with_aes(input_string, password, salt)
decrypted_value = decrypt_with_aes(encrypted_value, password, salt)

dns_records = {
    'example.com.': {
        dns.rdatatype.A: '192.168.1.101',
    },
    'safebank.com.': { dns.rdatatype.A: '192.168.1.102' },
    'google.com.': { dns.rdatatype.A: '192.168.1.103' },
    'legitsite.com.': { dns.rdatatype.A: '192.168.1.104' },
    'yahoo.com.': { dns.rdatatype.A: '192.168.1.105' },
    'nyu.edu.': {
        dns.rdatatype.A: '192.168.1.106',
        dns.rdatatype.TXT: encrypted_value.decode('utf-8'),
        dns.rdatatype.MX: [(10, 'mxa-00256a01.gslb.pphosted.com.')],
        dns.rdatatype.AAAA: '2001:0db8:85a3:0000:0000:8a2e:0373:7312',
        dns.rdatatype.NS: 'ns1.nyu.edu.',
    }
}

def run_dns_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(('127.0.0.1', 53))

    while True:
        data, addr = server_socket.recvfrom(1024)
        query = dns.message.from_wire(data)
        response = dns.message.make_response(query)
        
        for question in query.question:
            qname = question.name.to_text()
            qtype = question.rdtype

            if qname in dns_records:
                domain_records = dns_records[qname]
                if qtype in domain_records:
                    answer_data = domain_records[qtype]
                    if isinstance(answer_data, list):
                        for item in answer_data:
                            if qtype == dns.rdatatype.MX:
                                preference, exchange = item
                                rdata = MX(dns.rdataclass.IN, qtype, preference, exchange)
                            else:
                                rdata = dns.rdata.from_text(dns.rdataclass.IN, qtype, item)
                            response.answer.append(dns.rrset.from_text(qname, 3600, dns.rdataclass.IN, qtype, rdata.to_text()))
                    else:
                        rdata = dns.rdata.from_text(dns.rdataclass.IN, qtype, answer_data)
                        response.answer.append(dns.rrset.from_text(qname, 3600, dns.rdataclass.IN, qtype, rdata.to_text()))
                else:
                    response.set_rcode(dns.rcode.SERVFAIL)
            else:
                response.set_rcode(dns.rcode.NXDOMAIN)

        server_socket.sendto(response.to_wire(), addr)

def run_dns_server_user():
    print("Input 'q' and hit 'enter' to quit")
    print("DNS server is running...")

    def user_input():
        while True:
            cmd = input()
            if cmd.lower() == 'q':
                print('Quitting...')
                os.kill(os.getpid(), signal.SIGINT)

    input_thread = threading.Thread(target=user_input)
    input_thread.daemon = True
    input_thread.start()
    run_dns_server()


if __name__ == '__main__':
    run_dns_server_user()