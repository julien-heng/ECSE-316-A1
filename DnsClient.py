import sys
import socket


if __name__ == "__main__":

    parameters = {
        "timeout": "5",
        "max_retries": "3",
        "port": "53",
        "mail_name": "",
        "server": "",
        "name": ""
    }

    for i in range(1, len(sys.argv)):
        match sys.argv[i]:
            case "-t": 
                if sys.argv[i + 1].isdigit():
                    parameters["timeout"] = sys.argv[i + 1]
                    i = i + 1
            case "-r":
                if sys.argv[i + 1].isdigit():
                    parameters["max_retries"] = sys.argv[i + 1]
                    i = i + 1
            case "-p":
                if sys.argv[i + 1].isdigit():
                    parameters["port"] = sys.argv[i + 1]
                    i = i + 1
            case "-mx":
                parameters["mail_name"] = "mail"
            case "-nx":
                parameters["mail_name"] = "name"
            case _:
                if sys.argv[i][0] == "@":
                    parameters["server"] = sys.argv[i]
                    parameters["name"] = sys.argv[i + 1]

    for x in parameters:
        print(f"{x}:{parameters[x]}")
                


            