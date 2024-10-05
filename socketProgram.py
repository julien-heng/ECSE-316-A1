import socket

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

s.connect(("www.python.org", 80))


