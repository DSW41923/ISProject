import socket
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Hash import MD5

size = 65536
host = '127.0.0.1'
port = 5566

print("Start setting socket...", end='', flush=True)
mysock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# mysock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
print("Done", flush=True)

print("Connect to server...", end='', flush=True)
addr = (host, 5555)
mysock.connect(addr)
print("Done", flush=True)

print("Generate RSA key...", end='', flush=True)
random_generator = Random.new().read
key = RSA.generate(2048, random_generator)
print("Done", flush=True)

print("Exchange RSA public key with server...", end='', flush=True)
public_key = key.publickey().exportKey('DER')
mysock.sendall(public_key)
data = mysock.recv(size)
server_public_key = RSA.importKey(data)
print("Done", flush=True)

while True:
    # 3
    print("Waiting for notification from server...", end='', flush=True)
    data_3 = mysock.recv(size)
    print("Received!", flush=True)
    print("Sending auth code to server...", end='', flush=True)
    data = key.publickey().encrypt(data_3, 7)[0]
    h = MD5.new(data)
    data = h.hexdigest()
    data = server_public_key.encrypt(bytes(data, 'UTF-8'), 32)[0]
    header = bytes('0'*1024, 'UTF-8')
    h = MD5.new(header + data)
    trail = bytes(h.hexdigest(), 'UTF-8')
    data = header + data + trail
    mysock.sendall(data)
    print("Done", flush=True)
    # 3 check
    print("Authetication...", end='', flush=True)
    data = mysock.recv(size)
    try:
        check = data.decode('UTF-8')
        if check in ["Integrity check fail!", "Authetication fail!"]:
            print("Fail", flush=True)
            continue
        else:
            print("Success_1", flush=True)
            pass
    except:
        print("Success_2", flush=True)
        pass
    # 6
    print("Receiving new patch from server", flush=True)
    h = MD5.new(data[:-32])
    if(bytes(h.hexdigest(), 'UTF-8') != data[-32:]):
        continue
    else:
        pass
    patch = key.decrypt(data[1024:-32])
    patch_file = open("patch.dat", "wb")
    patch_file.write(patch)
    patch_file.close()
mysock.close()
