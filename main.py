import hashlib


class MerkelTreeNode:
    def __init__(self, data):
        self.leftLeaf = None
        self.rightLeaf = None
        self.data = data
        self.hashedData = hashlib.sha256(data.encode('utf-8'))


def addNode(data):
    dataArray.append(data)
    MerkelTreeNode(data)
    return

if __name__ == '__main__':
    dataArray=[]
    while True:
        usrInput = input()
        usrInputParsed = usrInput.split(" ")
        if usrInputParsed[0] == "1":
            addNode(usrInputParsed[1])
            print("invalid input!")
            continue
        x = 2
