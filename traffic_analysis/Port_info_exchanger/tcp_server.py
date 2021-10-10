import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((socket.gethostname(), 1234))

s.listen(5)

while True:
    clientSocket, address = s.accept()
    print(address)
    clientSocket.send(bytes("Welcome to server", "utf-8"))
