import hashlib


class MerkelTreeNode:
    def __init__(self, data):
        self.leftLeaf = None
        self.rightLeaf = None
        self.data = data
        self.hashedData = hashlib.sha256(data.encode('utf-8')).hexdigest()


def addNode(data):
    nodesArray.append(MerkelTreeNode(data))
    return


def calcRoot():
    if len(nodesArray) == 0:
        return 0
    elif len(nodesArray) == 1:
        return hashlib.sha256((nodesArray[0].hashedData).encode('utf-8')).hexdigest()
    else:
        for i in range(0, len(nodesArray), 2):
            node=nodesArray[i]
            node2=nodesArray[i+1]
            if node2 is None:
                finaTree.append(nodesArray[i])
                return
            combinedHash = node.hashedData + node2.hashedData
            parent = MerkelTreeNode(combinedHash)
            parent.leftLeaf = node
            parent.rightLeaf = node2
            finaTree.append(parent)



if __name__ == '__main__':
    nodesArray = []
    finaTree = []
    while True:
        usrInput = input()
        usrInputParsed = usrInput.split(" ")
        if usrInputParsed[0] == "1":
            addNode(usrInputParsed[1])
        elif usrInputParsed[0] == "2":
            result = calcRoot()
            if result:
                print(result)
            else:  # invalid input
                print("\n")
                continue
        else:
            print("invalid input!")
            continue
        x = 2
