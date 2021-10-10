import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((socket.gethostname(), 1234))

while True:
    data = s.recv(512)
    if ( len(data) < 1 ) :
        break
print(data)
