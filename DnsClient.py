import sys
import socket

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


if __name__ == "__main__":

    para = set_arguments(sys.argv)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((para["server"], para["port"]))
    print("connected")
    sock.close()
    print("closed")

    for x in para:
        print(f"{x}:{para[x]}")
                


            