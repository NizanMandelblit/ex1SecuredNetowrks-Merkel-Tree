import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
import base64


class MerkelTreeNode:
    def __init__(self, data):
        self.leftLeaf = None
        self.rightLeaf = None
        self.data = data
        self.numLeaf = None
        self.parent = None
        self.brother = None
        self.hashedData = hashlib.sha256(data.encode('utf-8')).hexdigest()


def addNode(data):
    newNode = MerkelTreeNode(data)
    newNode.numLeaf = len(nodesArray)
    nodesArray.append(newNode)
    return


def strProofRecrusive(requestedNode):
    if requestedNode.hashedData is finalTree[0].hashedData:  # if the requested node is the root
        return
    if requestedNode.brother is not None:
        print(" " + requestedNode.brother.hashedData, end='')
    if requestedNode.parent.hashedData != finalTree[0].hashedData:  # if his parent is not the root
        strProofRecrusive(requestedNode.parent)


# calculates the Proof Of Inclusion
def calcProofOfInclusion(index):
    requestedNode = nodesArray[int(index)]
    strProofRecrusive(requestedNode)


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
    alg = serialization.NoEncryption()
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=alg
    )
    with open("sk.pem", "wb") as f:
        f.write(pem)
        f.close()
    f = open("sk.pem", "rb")
    bSK = f.read()
    sSK = bSK.decode()
    print(sSK)
    f.close()
    public_key = private_key.public_key()
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open("pk.pem", "wb") as f:
        f.write(pem)
        f.close()
    f = open("pk.pem", "rb")
    bPK = f.read()
    sPK = bPK.decode()
    print(sPK)
    f.close()


def signRoot(root):
    with open("sk.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)
        message = bytes(root, 'utf-8')
        signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        encoded_signature = base64.b64encode(signature)
        decoded_signature = encoded_signature.decode()
        return decoded_signature


def verifyRoot(message, decoded_signature):
    with open("sk.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)
        encoded_signature = decoded_signature.encode(encoding='utf-8')
        signature = base64.b64decode(encoded_signature)
        message = bytes(message, 'utf-8')
        public_key = private_key.public_key()
        try:
            public_key.verify(
                signature, message, padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except:
            return False
        return True


def calcRoot(nodesArrayLocal):
    nodesArrayLen = len(nodesArrayLocal)
    if nodesArrayLen == 0:
        return None
    elif nodesArrayLen == 1:
        return nodesArrayLocal
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
                node.parent = parent
                node.brother = node2
                node2.parent = parent
                node2.brother = node
                finalTree.append(parent)
            nodesArrayLocal = []
            nodesArrayLocal = finalTree
        return finalTree


if __name__ == '__main__':
    nodesArray = []
    finalTree = []
    while True:
        usrInput = input()
        if usrInput == "":
            continue
        # usrInputParsed = usrInput.split(" ")
        if usrInput[0] == "1":
            addNode(usrInput[2:])
        elif usrInput[0] == "2":
            finalTree = calcRoot(nodesArray.copy())
            if finalTree is not None:
                print(finalTree[0].hashedData)
            else:  # invalid input
                print("\n")
                continue
        elif usrInput[0] == "3":
            finalTree = calcRoot(nodesArray)
            if finalTree is not None:
                print(finalTree[0].hashedData, end='')
            else:  # invalid input
                print("\n")
                continue
            calcProofOfInclusion(usrInput[2:])
            print("\n")
        elif usrInput[0] == "4":
            checkProofOfInclusion(finalTree)
        elif usrInput[0] == "5":
            calcKeys()
        elif usrInput[0] == "6":
            hashRoot = finalTree[0].hashedData
            sign = signRoot(hashRoot)
            print(sign)
        elif usrInput[0] == "7":
            hashRoot = finalTree[0].hashedData
            print(verifyRoot(hashRoot, usrInput[1]))
        else:
            print("invalid input!")
            continue
