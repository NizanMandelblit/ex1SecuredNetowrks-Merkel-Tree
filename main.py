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


def calcRoot(nodesArrayLocal):
    nodesArrayLen = len(nodesArrayLocal)
    if nodesArrayLen == 0:
        return 0
    elif nodesArrayLen == 1:
        return hashlib.sha256((nodesArrayLocal[0].hashedData).encode('utf-8')).hexdigest()
    else:
        while len(nodesArrayLocal) > 1:
            finaTree = []
            for i in range(0, len(nodesArrayLocal), 2):
                node = nodesArrayLocal[i]
                node2 = nodesArrayLocal[i + 1]
                if node2 is None:
                    finaTree.append(MerkelTreeNode(nodesArrayLocal[i]))
                    finaTree[0].leftLeaf = node
                    return
                combinedHash = node.hashedData + node2.hashedData
                parent = MerkelTreeNode(combinedHash)
                parent.leftLeaf = node
                parent.rightLeaf = node2
                finaTree.append(parent)
            nodesArrayLocal = []
            nodesArrayLocal = finaTree
        return finaTree[0].hashedData


if __name__ == '__main__':
    nodesArray = []
    finaTree = []
    while True:
        usrInput = input()
        usrInputParsed = usrInput.split(" ")
        if usrInputParsed[0] == "1":
            addNode(usrInputParsed[1])
        elif usrInputParsed[0] == "2":
            result = calcRoot(nodesArray)
            if result:
                print(result)
            else:  # invalid input
                print("\n")
                continue
        else:
            print("invalid input!")
            continue
        x = 2
