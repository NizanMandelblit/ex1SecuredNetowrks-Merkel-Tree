# Eldad Horvitz, 314964438, Nizan Mandelblit, 313
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


def getInput(conKey):
    while True:
        userInput = input()
        if userInput:
            conKey.append(userInput)
        else:
            break
    finalKey = '\n'.join(conKey)
    bytesKey = bytes(finalKey, 'utf-8')
    return bytesKey


def strProofRecrusive(requestedNode):
    if requestedNode.hashedData is finalTree[0].hashedData:  # if the requested node is the root
        return
    if requestedNode.brother is not None:
        if requestedNode.parent.leftLeaf == requestedNode.brother:
            print(" 0" + requestedNode.brother.hashedData, end='')
        else:
            print(" 1" + requestedNode.brother.hashedData, end='')
    if requestedNode.parent.hashedData != finalTree[0].hashedData:  # if his parent is not the root
        strProofRecrusive(requestedNode.parent)


# calculates the Proof Of Inclusion
def calcProofOfInclusion(index):
    requestedNode = nodesArray[int(index)]
    strProofRecrusive(requestedNode)


def checkProofOfInclusion(usrInput):
    usrInputSplitted = usrInput.split(" ")
    hashedData = hashlib.sha256(usrInputSplitted[0].encode('utf-8')).hexdigest()
    root = usrInputSplitted[1]
    leavesHashedData = usrInputSplitted[2:]
    for leaf in leavesHashedData:
        if leaf[0] == "0":
            hashedData = (leaf[1:] + hashedData)
        else:
            hashedData = (hashedData + leaf[1:])
        hashedData = hashlib.sha256(hashedData.encode('utf-8')).hexdigest()
    if hashedData == root:
        print("True")
    else:
        print("False")


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
    sk = pem.decode()
    print(sk)
    public_key = private_key.public_key()
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    pk = pem.decode()
    print(pk)


def signRoot(root, key):
    message = bytes(root, 'utf-8')
    signature = key.sign(
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


def verifyRoot(message, key, decoded_signature):
    encoded_signature = decoded_signature.encode(encoding='utf-8')
    signature = base64.b64decode(encoded_signature)
    message = bytes(message, 'utf-8')
    try:
        key.verify(
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


def defaultLevelHash():
    levelHash = hashlib.sha256(b'00').hexdigest()
    for i in range(255):
        defaultDict[i] = levelHash
        con = levelHash + levelHash
        levelHash = hashlib.sha256(con.encode('utf-8')).hexdigest()
    defaultDict[255] = levelHash


def getBrother(binData):
    if binData & 1:
        binData = binData >> 1
        binData = binData << 1
        return binData


def nondDfaultLevelHash(my_hexdata):
    scale = 16  # equals to hexadecimal
    num_of_bits = 256
    binData = bin(int(my_hexdata, scale))[2:].zfill(num_of_bits)
    nonDefaultDict[binData] = hashlib.sha256(b'01').hexdigest()
    for i in range(255):
        brother = getBrother(binData)
        if binData in nonDefaultDict.keys():
            continue
        else:
            continue
        binData = binData[:1]
    x = 2


if __name__ == '__main__':
    nodesArray = []
    finalTree = []
    sparseMerkelTreeArray = []
    defaultDict = {}
    nonDefaultDict = {}
    # smt = b'0000000000000000000000000000000000000000000000000000000000000000'
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
            checkProofOfInclusion(usrInput[2:])
        elif usrInput[0] == "5":
            calcKeys()
        elif usrInput[0] == "6":
            hashRoot = finalTree[0].hashedData
            userInput = usrInput[2:]
            conKey = []
            conKey.append(userInput)
            bytesKey = getInput(conKey)
            private_key = serialization.load_pem_private_key(bytesKey, password=None)
            sign = signRoot(hashRoot, private_key)
            print(sign)
        elif usrInput[0] == "7":
            userInput = usrInput[2:]
            conKey = []
            conKey.append(userInput)
            bytesKey = getInput(conKey)
            public_key = serialization.load_pem_public_key(bytesKey)
            nextInput = input()
            splitted = nextInput.split(' ')
            signInput = splitted[0]
            hashRoot = splitted[1]
            res = verifyRoot(hashRoot, public_key, signInput)
            print(res)
        elif usrInput[0] == "8":
            defaultLevelHash()
            nondDfaultLevelHash(usrInput[2:])
        elif usrInput[0] == "9":
            p = 9
        else:
            data = "1"
            one = hashlib.sha256(data.encode('utf-8')).hexdigest()
            print(one)
            data = "0"
            zero = hashlib.sha256(data.encode('utf-8')).hexdigest()
            print(zero)
            oo = one + one
            print(hashlib.sha256(oo.encode('utf-8')).hexdigest())
            oz = one + zero
            print(hashlib.sha256(oz.encode('utf-8')).hexdigest())
            zo = zero + one
            print(hashlib.sha256(zo.encode('utf-8')).hexdigest())
            zz = zero + zero
            print(hashlib.sha256(zz.encode('utf-8')).hexdigest())
            print("invalid input!")

            continue
