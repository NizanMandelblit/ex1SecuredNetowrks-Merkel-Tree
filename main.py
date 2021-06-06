# Eldad Horvitz, 314964438, Nizan Mandelblit, 313485468
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
import base64

# class for the regular tree
class MerkelTreeNode:
    def __init__(self, data):
        self.leftLeaf = None
        self.rightLeaf = None
        self.data = data
        self.numLeaf = None
        self.parent = None
        self.brother = None
        self.hashedData = hashlib.sha256(data.encode('utf-8')).hexdigest()

# add a node to tree
def addNode(data):
    newNode = MerkelTreeNode(data)
    newNode.numLeaf = len(nodesArray)
    nodesArray.append(newNode)
    return

# for input that has more than 1 line
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


#convert hex to binary
def hexToBin(my_hexdata):
    scale = 16  # equals to hexadecimal
    num_of_bits = 256
    return bin(int(my_hexdata, scale))[2:].zfill(num_of_bits)


#creat proof
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
    print("")


#checks the proof
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


#function makes random keys
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


#function makes a signature for the root
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


#the function verifies the root
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


#calculates the root
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


#finds the hash of each level in the default sparse tree
def defaultLevelHash():
    defaultDict[0] = '0'
    levelHash = hashlib.sha256(b'00').hexdigest()
    for i in range(255):
        defaultDict[i+1] = levelHash
        con = levelHash + levelHash
        levelHash = hashlib.sha256(con.encode('utf-8')).hexdigest()
    defaultDict[256] = levelHash
    V=7



#gets the brother's digest and its lsb
def getBrother(binData):
    length = len(binData)
    if binData[length-1] == '1':
        binData = binData[:length-1] + '0'
        return binData, 0
    else:
        binData = binData[:length-1] + '1'
        return binData, 1


# inserts not default value to the dictionary for those that need to be changed
def nondDfaultLevelHash(digest):
    binData = hexToBin(digest)
    length = len(binData)
    father = binData[:length - 1]
    nonDefaultDict[binData] = '1'
    brother, brotherLSB = getBrother(binData)
    if brother in nonDefaultDict.keys():
        nonDefaultDict[father] = hashlib.sha256(b'11').hexdigest()
    else:
        if binData[length-1] == '0':
            nonDefaultDict[father] = hashlib.sha256(b'10').hexdigest()
        else:
            nonDefaultDict[father] = hashlib.sha256(b'01').hexdigest()
    for i in range(255):
        binData = father
        length = len(binData)
        father = binData[:length - 1]
        brother, brotherLSB = getBrother(binData)
        if brother in nonDefaultDict.keys():
            if brotherLSB == 1:
                con = nonDefaultDict[binData] + nonDefaultDict[brother]
            else:
                con = nonDefaultDict[brother] + nonDefaultDict[binData]
            nonDefaultDict[father] = hashlib.sha256(con.encode('utf-8')).hexdigest()
        else:
            if brotherLSB == 1:
                con = nonDefaultDict[binData] + defaultDict[i+1]
            else:
                con = defaultDict[i+1] + nonDefaultDict[binData]
            nonDefaultDict[father] = hashlib.sha256(con.encode('utf-8')).hexdigest()


# gets the root of the sparse tree
def getRoot():
    rootBinData=''
    if rootBinData in nonDefaultDict.keys():
        return nonDefaultDict[rootBinData]
    else:
        return defaultDict[256]

# makes Proof Of Inclusion
def calcSparseProofOfInclusion(digest):
    output=""
    default = 0
    binData = hexToBin(digest)
    length = len(binData)
    father = binData[:length - 1]
    brother, brotherLSB = getBrother(binData)
    if brother in nonDefaultDict.keys():
        output = output + " " + nonDefaultDict[brother]
        default = 1
    elif binData in nonDefaultDict.keys():
        output = output + " " + defaultDict[0]
        default = 1
    for i in range(255):
        binData = father
        length = len(binData)
        father = binData[:length - 1]
        brother, brotherLSB = getBrother(binData)
        if default == 1:
            if brother in nonDefaultDict.keys():
                output = output + " " + nonDefaultDict[brother]
            else:
                output = output + " " + defaultDict[i + 1]
        elif brother in nonDefaultDict.keys():
            default = 1
            output = output + " " + defaultDict[i + 1]
            output = output + " " + nonDefaultDict[brother]
    if default == 0:
        output = output + " " + defaultDict[256]
    return output


# checks Proof Of Inclusion
def checkSparseProofOfInclusion(us):
    usrInputSplitted = us.split(" ")
    digest = usrInputSplitted[0]
    binData = hexToBin(digest)
    length = len(binData)
    val = usrInputSplitted[1]
    root = usrInputSplitted[2]
    proof = usrInputSplitted[3:]
    proofSize = len(proof)
    brother, brotherLSB = getBrother(binData)
    lastDefaultLevel = -1
    lastDefaultValue = hashlib.sha256(b'00').hexdigest()
    if val == '1' and proof[0] == '1':
        lastDefaultValue = hashlib.sha256(b'11').hexdigest()
        lastDefaultLevel = 0
    elif val == '0' and proof[0] == '1':
        lastDefaultLevel = 0
        if brotherLSB == 1:
            lastDefaultValue = hashlib.sha256(b'01').hexdigest()
        else:
            lastDefaultValue = hashlib.sha256(b'10').hexdigest()
    elif val == '1' and proof[0] != '1':
        lastDefaultLevel = 0
        if brotherLSB == 0:
            lastDefaultValue = hashlib.sha256(b'01').hexdigest()
        else:
            lastDefaultValue = hashlib.sha256(b'10').hexdigest()
    if lastDefaultLevel == 0:
        if proofSize != 256:
            return False
        lastDefaultLevel = 1
    if lastDefaultLevel == -1:
        for j in range(256):
            if defaultDict[j + 1] == proof[0]:
                lastDefaultLevel = j+1
                lastDefaultValue = proof[0]
                break
        if lastDefaultLevel + proofSize != 257:
            return False
    if lastDefaultLevel == -1:
        return False
    prev = lastDefaultValue
    for k in range(proofSize - 1):
        lsb = binData[length - (k + 1 + lastDefaultLevel)]
        if lsb == "0":
            con = prev + proof[k + 1]
        else:
            con = proof[k + 1] + prev
        prev = hashlib.sha256(con.encode('utf-8')).hexdigest()
    if prev == root:
        return True
    else:
        return False

if __name__ == '__main__':
    nodesArray = []
    finalTree = []
    sparseMerkelTreeArray = []
    defaultDict = {}
    defaultLevelHash()
    nonDefaultDict = {}
    while True:
        usrInput = input()
        if usrInput == "":
            print("\n")
        # usrInputParsed = usrInput.split(" ")
        if usrInput[0] == "1" and usrInput[1] == " ":
            addNode(usrInput[2:])
        elif usrInput[0] == "2":
            finalTree = calcRoot(nodesArray.copy())
            if finalTree is not None:
                print(finalTree[0].hashedData)
            else:  # invalid input
                print("")
                continue
        elif usrInput[0] == "3":
            finalTree = calcRoot(nodesArray)
            if finalTree is not None:
                print(finalTree[0].hashedData, end='')
            else:  # invalid input
                print("")
            calcProofOfInclusion(usrInput[2:])
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
            nondDfaultLevelHash(usrInput[2:])
        elif usrInput[0] == "9":
            print(getRoot())
        elif usrInput[0] == "1" and usrInput[1] == "0":
            print(getRoot()+calcSparseProofOfInclusion(usrInput[3:]))
        elif usrInput[0] == "1" and usrInput[1] == "1":
            print(checkSparseProofOfInclusion(usrInput[3:]))
        else:
            print("")

