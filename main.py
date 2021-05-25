import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

class MerkelTreeNode:
    def __init__(self, data):
        self.leftLeaf = None
        self.rightLeaf = None
        self.data = data
        self.hashedData = hashlib.sha256(data.encode('utf-8')).hexdigest()


def addNode(data):
    nodesArray.append(MerkelTreeNode(data))
    return
# calculates the Proof Of Inclusion
def calcProofOfInclusion(index,tree):
    proof = []

    return proof


def checkProofOfInclusion(data):
    nodesArray.append(MerkelTreeNode(data))
    proof = []

    return proof
def calcKeys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key,public_key

def signRoot(root,key):
    message = root
    signature = key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verifyRoot(root):
    public_key.verify(
        signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def calcRoot(nodesArrayLocal):
    nodesArrayLen = len(nodesArrayLocal)
    if nodesArrayLen == 0:
        return 0
    elif nodesArrayLen == 1:
        return nodesArrayLocal[0].hashedData
    else:
        while len(nodesArrayLocal) > 1:
            finalTree = []
            for i in range(0, len(nodesArrayLocal), 2):
                node = nodesArrayLocal[i]
                if i + 1 >= len(nodesArrayLocal):
                    finalTree.append(nodesArrayLocal[i])
                    break
                node2 = nodesArrayLocal[i + 1]
                combinedHash = node.hashedData + node2.hashedData
                parent = MerkelTreeNode(combinedHash)
                parent.leftLeaf = node
                parent.rightLeaf = node2
                finalTree.append(parent)
            nodesArrayLocal = []
            nodesArrayLocal = finalTree
        return finalTree[0].hashedData


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
        elif usrInputParsed[0] == "3":
            proof = calcProofOfInclusion(usrInputParsed[1], finaTree)
        elif usrInputParsed[0] == "4":
            checkProofOfInclusion(finaTree)
        elif usrInputParsed[0] == "5":
            private_key, public_key = calcKeys()
        elif usrInputParsed[0] == "6":
            signature = signRoot(finaTree,usrInputParsed[1])
        elif usrInputParsed[0] == "7":
            signature = verifyRoot(finaTree, usrInputParsed[1])

        else:
            print("invalid input!")
            continue
        x = 2
