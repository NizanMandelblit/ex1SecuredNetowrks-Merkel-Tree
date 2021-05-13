import hashlib


class MerkelTreeA:
    def __init__(self, data):
        self.leftNode = None
        self.rightNode = None
        self.data = data
        self.hashedData = hashlib.sha256(data)


def addNode(data):
    return


if __name__ == '__main__':
    while True:
        usrInput = input()
        usrInputParsed = usrInput.split(" ")
        if usrInputParsed[0] == "1":
            addNode(usrInputParsed[1])
            print("invalid input!")
            continue
        x = 2
