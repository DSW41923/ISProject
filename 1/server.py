import socket
import threading
from Crypto.PublicKey import RSA
from Crypto.Hash import MD5
from Crypto import Random

threads = []


def threadWork_Listen(sock):
    print("Wait Connection...", flush=True)
    while True:
        clientsock, clientaddr = sock.accept()
        print("-----------------------------------------------------", flush=True)
        print("Connected from client IP Address:" + str(clientaddr), flush=True)
        threads.append(threading.Thread(target=threadWork_RSA, args=(clientsock,)))
        threads[-1].start()
        threads[-1].join()


def threadWork_RSA(client):
    print("Exchange RSA public key with client...", end='', flush=True)
    public_key = key.publickey().exportKey('DER')
    data = client.recv(size)
    client_public_key = RSA.importKey(data)
    client_data.append((client, client_public_key))
    client.sendall(public_key)
    print("Done", flush=True)
    print("-----------------------------------------------------", flush=True)
    print("Upload new patch by entering file path:", flush=True)


def threadWork_Update(client_data, patch):
    # 1.9
    msg = "New Patch Available!"
    auth_code = client_data[1].encrypt(bytes(msg, 'UTF-8'), 32)[0]
    h = MD5.new(auth_code)
    authorized_code.append(h.hexdigest())

    while True:
        # 2
        print("Sending new patch notification to client...", end='', flush=True)
        msg = "New Patch Available!"
        client_data[0].sendall(bytes(msg, 'UTF-8'))
        print("Done", flush=True)
        # 4
        print("Autheticating client...", end='', flush=True)
        data = client_data[0].recv(size)
        h = MD5.new(data[:-32])
        if(bytes(h.hexdigest(), 'UTF-8') != data[-32:]):
            msg = "Integrity check fail!"
            print(msg, flush=True)
            client_data[0].sendall(bytes(msg, 'UTF-8'))
            continue
        elif key.decrypt(data[1024:-32]).decode('UTF-8') not in authorized_code:
            msg = "Authetication fail!"
            print(msg, flush=True)
            client_data[0].sendall(bytes(msg, 'UTF-8'))
            continue
        else:
            print("Done", flush=True)
            break
    # 5
    print("Sending new patch to client...", end='', flush=True)
    data = client_data[1].encrypt(patch, 32)[0]
    header = bytes('0'*1024, 'UTF-8')
    h = MD5.new(header + data)
    trail = bytes(h.hexdigest(), 'UTF-8')
    data = header + data + trail
    client_data[0].sendall(data)
    print("Done", flush=True)

size = 65536
host = '127.0.0.1'
port = 5555

print("Start setting socket...", end='', flush=True)
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind((host, port))
sock.listen(5)
print("Done", flush=True)

client_data = []
authorized_code = []

print("Generate RSA key...", end='', flush=True)
random_generator = Random.new().read
key = RSA.generate(2048, random_generator)
print("Done", flush=True)
threading.Thread(target=threadWork_Listen, args=(sock,), daemon=True).start()

while True:
    if len(client_data) != 0:
        if len(threads) != 0:
            try:
                threads[-1].join()
            except:
                pass
            # 1
            path = input()
            patch = open(path, "rb").read()
            threads = []
            for x in client_data:
                threads.append(threading.Thread(target=threadWork_Update, args=(x, patch,)))
            for t in threads:
                t.start()
                t.join()
            print("Upload new patch by entering file path:", flush=True)
sock.close()
