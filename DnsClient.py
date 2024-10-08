import sys
import socket
import random
import time

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

def dns_question(parameters):

    # QNAME representation in bytes
    qname = b''
    labels = parameters["name"].split(".")
    for label in labels:
        l = len(label)
        qname = qname + l.to_bytes()
        for i in range(l):
            qname = qname + bytes(label[i], 'utf-8')
    qname = qname + (0).to_bytes()
    
    # QTYPE representation in bytes
    if parameters["type"] == "A":
        qtype = (0x00).to_bytes() + (0x01).to_bytes()
    elif parameters["type"] == "NX":
        qtype = (0x00).to_bytes() + (0x0f).to_bytes()
    else: 
        qtype = (0x00).to_bytes() + (0x02).to_bytes()
    
    #QCLASS representation in bytes
    qclass = (0x00).to_bytes() + (0x01).to_bytes()

    question = qname + qtype + qclass
    return question

def dns_header():

    header = 0x0

    # ID reprensentation in hex 
    id = random.randint(0x0000, 0xffff)
    header = header | id

    # QR = 0 for queries
    qr = 0x0
    header = header << 1 | qr

    # OPCODE = 0 for standard query
    opcode = 0x0
    header = header << 4 | opcode

    # AA only meaningful in responses
    aa = 0x0 
    header = header << 1 | aa

    # TC indicates if message was truncated
    tc = 0x0
    header = header << 1 | tc

    # RD = 1 for recursive query
    rd = 0x1 
    header = header << 1 | rd

    # RA indicates if server supports recursive queries
    ra = 0x0
    header = header << 1 | ra

    # Z to be set to 0
    z = 0x0
    header = header << 3 | z

    # RCODE only meaningful in responses
    rcode = 0x0
    header = header << 4 | rcode

    # QDCOUNT always 1 
    qdcount = 1
    header = header << 16 | qdcount

    # ANCOUNT = number of resource records 
    ancount = 0
    header = header << 16 | ancount

    # NSCOUNT ignored
    nscount = 0
    header = header << 16 | nscount

    # ARCOUNT
    arcount = 0
    header = header << 16 | arcount

    return header.to_bytes(12)
     
def send_query(parameters, packet):
    # set up socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect((parameters["server"], parameters["port"]))
    sock.settimeout(parameters["timeout"])

    attempts = 0
    answer = b''
    duration = 0
    while attempts < parameters["max_retries"]:
        try:
            start_time = time.time()
            sock.send(packet)
            answer = sock.recv(1024)
            while answer == b'':
                answer = sock.recv(1024)
            end_time = time.time()
            duration = end_time - start_time
            attempts += 1
            break
        except TimeoutError:
            attempts += 1

    sock.close()
    print(answer)
    print(f"{duration} s")
    print(f"{attempts} attempts")




if __name__ == "__main__":
    
    # Set up packet for query
    parameters = set_arguments(sys.argv)
    packet = dns_header() + dns_question(parameters)

    # send and receive packets
    send_query(parameters, packet)

    
    

    

    
    



    
                


            