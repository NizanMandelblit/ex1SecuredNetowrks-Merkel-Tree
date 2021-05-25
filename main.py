import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization


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
    alg=serialization.NoEncryption()
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=alg
    )
    with open("sk.pem", "wb") as f:
        f.write(pem)
        f.close()
    f = open("sk.pem", "rb")
    bSK=f.read()
    sSK=bSK.decode()
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
        print(signature)
        print(signature.decode())

        public_key = private_key.public_key()
        return public_key.verify(
            signature, message, padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

def verifyRoot(message):
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
        return None
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
        return finalTree


if __name__ == '__main__':
    nodesArray = []
    finalTree = []
    while True:
        usrInput = input()
        usrInputParsed = usrInput.split(" ")
        if usrInputParsed[0] == "1":
            addNode(usrInputParsed[1])
        elif usrInputParsed[0] == "2":
            finalTree = calcRoot(nodesArray)
            if finalTree is not None:
                print(finalTree[0].hashedData)
            else:  # invalid input
                print("\n")
                continue
        elif usrInputParsed[0] == "3":
            proof = calcProofOfInclusion(usrInputParsed[1], finalTree)
        elif usrInputParsed[0] == "4":
            checkProofOfInclusion(finalTree)
        elif usrInputParsed[0] == "5":
            calcKeys()
        elif usrInputParsed[0] == "6":
            fds=bytes(usrInputParsed[1], 'utf-8')
            rsa.PrivateKey.load_pkcs1(fds)
            rit = "root"
            hashRoot=hashlib.sha256(rit.encode('utf-8')).hexdigest()
            sign = signRoot(hashRoot)
            print(sign)
        elif usrInputParsed[0] == "7":
            signa = verifyRoot(finalTree, usrInputParsed[1])

        else:
            print("invalid input!")
            continue

