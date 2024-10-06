import sys
import socket
import random

def set_arguments(args):
    parameters = {
        "timeout": 5,
        "max_retries": 3,
        "port": 53,
        "type": "A",
        "server": "",
        "name": ""
    }

    for i in range(1, len(args)):
        if args[i] == "-t":
            if args[i + 1].isdigit():
                    parameters["timeout"] = int(args[i + 1])
                    i = i + 1
        elif args[i] == "-r":
            if args[i + 1].isdigit():
                    parameters["max_retries"] = int(args[i + 1])
                    i = i + 1
        elif args[i] == "-p":  
            if args[i + 1].isdigit():
                    parameters["port"] = int(args[i + 1])
                    i = i + 1  
        elif args[i] == "-mx":
            parameters["type"] = "MX"
        elif args[i] == "-nx":   
            parameters["type"] = "NX"  
        elif args[i][0] == "@":
            parameters["server"] = args[i][1:]
            parameters["name"] = args[i + 1]  

    return parameters


def header():
    # need to generate unique id 
    id = hex(random.randint(0, 65535))
    print(id)

    # QR will always be 0 since we are only sending queries to server
    qr = 0

    # OPCode = 0 for standard query
    opcode = 0

    # AA only meaningful in responses
    aa = 0 

    # TC indicates if message was truncated
    tc = 0

    # RD = 1 for recursive query
    rd = 1 

    # RA indicates if server supports recursive queries
    ra = 0

    # Z to be set to 0
    z = 0

    # Rcode only meaningful in responses
    rcode = 0

    # QDcount always 1 
    qdcount = 1

    # Ancount
    ancount = 0

    nscount = 0

    arcount = 0

def qname(name):
    qname = 0
    labels = name.split(".")
    for label in labels:
        l = len(label)
        qname = qname << 8 | l
        for i in range(l):
            qname = qname << 8 | ord(label[i])
    return hex(qname)




     



if __name__ == "__main__":
    """ 
    para = set_arguments(sys.argv)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    sock.connect((para["server"], para["port"]))
    print("connected")
    sock.close()
    print("closed")
    for x in para:
        print(f"{x}:{para[x]}")
    """
    print(qname("www.mcgill.ca"))
    
                


            