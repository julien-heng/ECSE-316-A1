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
            else:
                print(f"ERROR\tIncorrect input syntax: expected number after argument {args[i]}")
                return None
        elif args[i] == "-r":
            if args[i + 1].isdigit():
                parameters["max_retries"] = int(args[i + 1])
                i = i + 1
            else:
                print(f"ERROR\tIncorrect input syntax: expected number after argument {args[i]}")
                return None
        elif args[i] == "-p":  
            if args[i + 1].isdigit():
                parameters["port"] = int(args[i + 1])
                i = i + 1 
            else:
                print(f"ERROR\tIncorrect input syntax: expected number after argument {args[i]}")
                return None
        elif args[i] == "-mx":
            if parameters["type"] != "A":
                print(f"ERROR\tIncorrect input syntax: unexpected argument {args[i]}")
                return None
            parameters["type"] = "MX"
        elif args[i] == "-ns":
            if parameters["type"] != "A":
                print(f"ERROR\tIncorrect input syntax: unexpected argument {args[i]}")
                return None 
            parameters["type"] = "NS"  
        elif args[i][0] == "@":
            parameters["server"] = args[i][1:]
            parameters["name"] = args[i + 1] 
            if i != len(args) - 2:
                print(f"ERROR\tIncorrect input syntax: unexpected argument {args[i+2]}")
                return None
            else:
                return parameters
        elif args[i].isdigit():
            print(f"ERROR\tIncorrect input syntax: unexpected argument {args[i]}")
            return None
        else:
            print(f"ERROR\tIncorrect input syntax: unexpected argument {args[i]}")
            return None

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
    elif parameters["type"] == "NS":
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

    retries = 0
    answer = b''
    duration = 0
    while retries < parameters["max_retries"]:
        try:
            start_time = time.time()
            sock.send(packet)
            if retries == 0:
                print(f"DnsClient sending request for {parameters['name']}")
                print(f"Server: {parameters['server']}")
                print(f"Request type: {parameters['type']}")
            answer = sock.recv(1024)
            while answer == b'':
                answer = sock.recv(1024)
            end_time = time.time()
            duration = end_time - start_time
            print(f"Response received after {round(duration, 5)} seconds ({retries} retries)")
            break
        except TimeoutError:
            retries += 1

    sock.close()
    if answer == b'':
        print(f"ERROR\tMaximum number of retries {parameters['max_retries']} exceeded")
        return 
    
    packet_id = (packet[0] << 8) | packet[1]
    answer_id = (answer[0] << 8) | answer[1]
    if packet_id != answer_id:
        print(f"ERROR\tUnexpected response")
        return 

    return parse_dns_answer(answer, len(packet))

def parse_dns_answer(answer, l):

    # ANCOUNT 
    ancount = (answer[6] << 8) | answer[7]
    # ARCOUNT
    arcount = (answer[10] << 8) | answer[11]

    # no record found 
    if ancount == 0:
        print(f"NOTFOUND")
        return

    # AA
    aa = (answer[2] & 0b00000100) >> 2
    if aa == 1:
        aa = 'auth'
    else:
        aa = 'nonauth'

    print(f"***Answer Section ({ancount} records)***")

    start_index = l
    for i in range(ancount):

        # NAME 
        result = parse_name(answer, start_index)
        name = result[1]
        type_index = result[0]

        # TYPE 
        type_rdata = (answer[type_index] << 8) | answer[type_index + 1]

        # TTL
        ttl_index = type_index + 4
        ttl = (answer[ttl_index] << 8) | answer[ttl_index + 1]
        ttl = (ttl << 8) | answer[ttl_index + 2]
        ttl = (ttl << 8) | answer[ttl_index + 3]

        # RDLENGTH
        rdlength = (answer[ttl_index + 4] << 8) | answer[ttl_index + 5]

        # RDATA
        rdata_index = ttl_index + 6
        if type_rdata == 0x1:
            rdata = '.'.join([str(answer[rdata_index + i]) for i in range(4)])
            start_index = rdata_index + 4
            print(f"IP\t{rdata}\t{ttl}\t{aa}")
        elif type_rdata == 0x2:
            result = parse_name(answer, rdata_index)
            rdata = result[1]
            start_index = rdata_index + rdlength
            print(f"NS\t{rdata}\t{ttl}\t{aa}")
        elif type_rdata == 0x5:
            result = parse_name(answer, rdata_index)
            rdata = result[1]
            start_index = rdata_index + rdlength
            print(f"CNAME\t{rdata}\t{ttl}\t{aa}")
        else :
            preference = (answer[rdata_index] << 8) | answer[rdata_index + 1]
            result = parse_name(answer, rdata_index + 2)
            rdata = result[1]
            start_index = rdata_index + rdlength
            print(f"MX\t{rdata}\t{preference}\t{ttl}\t{aa}")

    # parsing additional records the same answers are parsed

    print(f"***Additional Section ({arcount} records)***")

    for j in range(arcount):

        # NAME 
        result = parse_name(answer, start_index)
        name = result[1]
        type_index = result[0]

        # TYPE 
        type_rdata = (answer[type_index] << 8) | answer[type_index + 1]

        # TTL
        ttl_index = type_index + 4
        ttl = (answer[ttl_index] << 8) | answer[ttl_index + 1]
        ttl = (ttl << 8) | answer[ttl_index + 2]
        ttl = (ttl << 8) | answer[ttl_index + 3]

        # RDLENGTH
        rdlength = (answer[ttl_index + 4] << 8) | answer[ttl_index + 5]

        # RDATA
        rdata_index = ttl_index + 6
        if type_rdata == 0x1:
            rdata = '.'.join([str(answer[rdata_index + i]) for i in range(4)])
            start_index = rdata_index + 4
            print(f"IP\t{rdata}\t{ttl}\t{aa}")
        elif type_rdata == 0x2:
            result = parse_name(answer, rdata_index)
            rdata = result[1]
            start_index = rdata_index + rdlength
            print(f"NS\t{rdata}\t{ttl}\t{aa}")
        elif type_rdata == 0x5:
            result = parse_name(answer, rdata_index)
            rdata = result[1]
            start_index = rdata_index + rdlength
            print(f"CNAME\t{rdata}\t{ttl}\t{aa}")
        else :
            preference = (answer[rdata_index] << 8) | answer[rdata_index + 1]
            result = parse_name(answer, rdata_index + 2)
            rdata = result[1]
            start_index = rdata_index + rdlength
            print(f"MX\t{rdata}\t{preference}\t{ttl}\t{aa}")

def parse_name(answer, start_index):
    next_index = 0
    compressed = (answer[start_index] >> 6) == 0b11

    if compressed:
        offset = (answer[start_index] & 0b00111111) << 8 | answer[start_index + 1]
        next_index = start_index + 2
    else:
        offset = start_index

    parse = True
    name = ''

    while parse:

        length = answer[offset]
        for k in range(length):
            name += chr(answer[offset + 1 + k])

        if answer[offset + length + 1] == 0:
            parse = False
            if next_index < offset + length + 2:
                next_index = offset + length + 2
        elif (answer[offset + length + 1] >> 6) == 0b11 :  
            if next_index < offset + length + 3:
                next_index = offset + length + 3
            offset = (answer[offset + length + 1] & 0b00111111) << 8 | answer[offset + length + 2]
        else:
            offset = offset + length + 1  
            name = name + '.'

    
    return [next_index, name]


if __name__ == "__main__":
    
    # Set up packet for query
    parameters = set_arguments(sys.argv)

    if parameters is not None:
        packet = dns_header() + dns_question(parameters)
  
        # send and receive packets
        response = send_query(parameters, packet)
    

    
    

    

    
    



    
                


            