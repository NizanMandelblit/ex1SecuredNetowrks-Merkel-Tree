import hashlib

if __name__ == '__main__':
    while True:
        usrInput = input()
        usrInputParsed = usrInput.split(" ")
        if usrInputParsed[0] == "1":
            print("invalid input!")
            continue
        x = 2
