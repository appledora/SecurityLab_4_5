import hashlib
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Cipher import AES
import time
import os
import pandas as pd
import matplotlib.pyplot as plt
from base64 import b64encode, b64decode
from Cryptodome.Util.Padding import pad, unpad

import json
import warnings
warnings.filterwarnings("ignore")
'''
source : https://pycryptodome.readthedocs.io/en/latest/src/examples.html#generate-public-key-and-private-key
https://pycryptodome.readthedocs.io/en/latest/src/cipher/classic.html
'''


def write_to_CSV(df):
    if not os.path.isfile(os.getcwd()+'/lab4/ExecutionLog.csv'):
        df.to_csv(os.getcwd()+'/lab4/ExecutionLog.csv')
    else:  # else it exists so append without writing the header
        df.to_csv(os.getcwd()+'/lab4/ExecutionLog.csv', mode='a', header=False)


def plot_data(logtype="RSA"):
    print(logtype, type(logtype))
    filename = input("Type a name for the plot: ")
    if (os.path.exists(os.getcwd()+"/lab4/ExecutionLog.csv")):
        df = pd.read_csv(os.getcwd()+"/lab4/ExecutionLog.csv")
        # df = df[]
        df = df[df['type'].astype("string").str.contains(logtype)]
        # print(df.to_markdown())
        df_pivot = pd.pivot_table(
            df,
            index="type",
            columns="keyLen",
            values=["filesize", "time"],
        )
        # Plot a bar chart using the DF
        ax = df_pivot.plot(kind="bar")
        ax.set_yscale("log")
        # Get a Matplotlib figure from the axes object for formatting purposes
        fig = ax.get_figure()
        # Change the plot dimensions (width, height)
        fig.set_size_inches(7, 6)
        plt.xticks(rotation=0)
        plt.savefig(os.getcwd()+"/lab4/plots/"+filename+".png")

        plt.show()

    else:
        print("No pre-existing data.")
        main()


def RSAKeyGenerate(keylen):
    print("Generating keypair for keylength: ", keylen)
    keypair = RSA.generate(int(keylen))
    private_key = keypair.export_key()
    file_out = open(str(os.getcwd())+"/lab4/keys/private-" +
                    str(keylen)+".pem", "wb+")
    file_out.write(private_key)
    file_out.close()

    pubKey = keypair.publickey()
    # print(f"Public key:  (n={hex(pubKey.n)}, e={hex(pubKey.e)})")
    pubKeyPEM = pubKey.exportKey()
    file_out = open(str(os.getcwd())+"/lab4/keys/public-" +
                    str(keylen)+".pem", "wb+")
    file_out.write(pubKeyPEM)
    file_out.close()

    print("Keys are stored in ",  os.getcwd()+"/lab4/keys/ folder")


def RSA_encryption(keylen, filename="Encrypted_data"):
    RSAKeyGenerate(keylen)
    print("Starting Encryption using ", keylen, "-bit key .....")
    data = input("Type your plaintext data:")
    """
    Since we want to be able to encrypt an arbitrary amount of data,
    we use a hybrid encryption scheme. We use RSA with PKCS#1 OAEP for asymmetric encryption of an AES session key.
    The session key can then be used to encrypt all the actual data.
    """
    file_out = open(
        os.getcwd()+"/lab4/data/"+filename+".bin", "wb")
    recipient_key = RSA.import_key(
        open(os.getcwd()+"/lab4/keys/public-"+str(keylen)+".pem").read())
    session_key = get_random_bytes(16)
    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)
    # Encrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data.encode("utf-8"))
    [file_out.write(x)
     for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext)]
    file_out.close()
    print("Encrypted ", filename+".bin saved in data/ folder")


def RSA_decryption(keylen, filename):
    print("Starting Decryption of ", filename+".bin.....")
    file_in = open(
        os.getcwd()+"/lab4/data/"+filename+".bin", "rb")
    private_key = RSA.import_key(
        open(os.getcwd()+"/lab4/keys/private-"+str(keylen)+".pem").read())
    enc_session_key, nonce, tag, ciphertext = \
        [file_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1)]
    # Decrypt the session key with the private RSA key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)
    # Decrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    print("Decrypted Plaintext: ", data.decode("utf-8"))


def RSA_(keylen=1024):
    objType = int(
        input("Choose one of the options:\n1. Encrypt Data\n2. Decrypt Data\n"))
    filename = input("Type file name for your encrypted data: ")
    if (objType == 1):
        start_time = time.time()
        RSA_encryption(keylen, filename)
        end_time = time.time() - start_time
        df = pd.DataFrame.from_records([{
            "type": "RSA_encryption",
            "keyLen": int(keylen),
            "filesize": os.path.getsize(os.getcwd()+"/lab4/data/"+filename+".bin"),
            "time": end_time
        }])
        write_to_CSV(df)
    elif (objType == 2):
        start_time = time.time()
        RSA_decryption(keylen, filename)
        end_time = time.time() - start_time
        df = pd.DataFrame.from_records([{
            "type": "RSA_decryption",
            "keyLen": int(keylen),
            "filesize": os.path.getsize(os.getcwd()+"/lab4/data/"+filename+".bin"),
            "time": end_time
        }])
        write_to_CSV(df)


def AES_key_generation(keylen, mode):
    key = get_random_bytes(keylen)
    print("Generating cipher object in mode : ", str(mode))
    # Create a AES cipher object with the key using the mode
    cipher = AES.new(key, mode)
    file_out = open(os.getcwd()+"/lab4/keys/AESKey-" +
                    str(keylen)+"-"+str(mode)+".bin", "wb")  # wb = write bytes
    file_out.write(key)
    file_out.close()
    return cipher


def AES_encryption(keylen, filename, data, mode):
    BLOCK_SIZE = 32
    cipher = AES_key_generation(keylen, mode)  # in byte
    print("Starting Encryption using ", keylen, "-bit key in mode ", str(mode))
    if (mode == AES.MODE_ECB):
        ct_bytes = cipher.encrypt(pad(data.encode("utf-8"), BLOCK_SIZE))
        ct = b64encode(ct_bytes).decode('utf-8')
        result = json.dumps({"ciphertext": ct})
    elif (mode == AES.MODE_CFB):
        mode = AES.MODE_CFB
        ct_bytes = cipher.encrypt(data.encode("utf-8"))
        iv = b64encode(cipher.iv).decode('utf-8')
        ct = b64encode(ct_bytes).decode('utf-8')
        result = json.dumps({'iv': iv, 'ciphertext': ct})
        print(result)
    print("Generating cipher object in mode : ", mode)

    with open(
            os.getcwd()+"/lab4/data/"+filename+".json", "w") as f:
        json.dump(result, f)


def AES_decryption(keylen, filename, mode):
    print("Starting Decryption of ", filename+".json.....")
    key_in = open(os.getcwd()+"/lab4/keys/AESKey-" +
                  str(keylen)+"-"+str(mode)+".bin", "rb").read()
    print("key_in:\n", key_in)
    json_file_path = os.getcwd()+"/lab4/data/"+filename+".json"
    with open(json_file_path) as f:
        bb = json.load(f)
    b64 = json.loads(bb)

    modeType = int(input("Pick a mode for AES :\n1. ECB\n2. CFB\n"))
    mode = None
    if (modeType == 1):
        mode = AES.MODE_ECB
        cipher = AES.new(key_in, mode)
    else:
        mode = AES.MODE_CFB
        iv = b64decode(b64["iv"])
        cipher = AES.new(key_in, mode, iv=iv)

    ct = b64decode(b64["ciphertext"])
    print("Generating cipher object in mode : ", mode)
    pt = cipher.decrypt(ct)
    print("The message was: ", pt)


def AES_(keylen=128):
    objType = int(
        input("Choose one of the options:\n1. Encrypt Data\n2. Decrypt Data\n"))
    filename = input("Type file name for your encrypted data: ")
    modeType = int(
        input("Pick a mode for AES key generation :\n1. ECB\n2. CFB\n"))
    mode = None
    if (modeType == 1):
        mode = AES.MODE_ECB
    else:
        mode = AES.MODE_CFB
    if (objType == 1):
        data = input("Type your plaintext data:")
        start_time = time.time()
        AES_encryption(keylen, filename, data, mode)
        end_time = time.time() - start_time
        print("Endtime: ", end_time)

        df = pd.DataFrame.from_records([{
            "type": "AES_Encryption",
            "keyLen": int(keylen),
            "filesize": os.path.getsize(os.getcwd()+"/lab4/data/"+filename+".json"),
            "time": end_time
        }])
        write_to_CSV(df)
    elif (objType == 2):
        start_time = time.time()
        AES_decryption(keylen, filename, mode)
        end_time = time.time() - start_time
        print("Endtime: ", end_time)
        df = pd.DataFrame.from_records([{
            "type": "AES_decryption",
            "keyLen": int(keylen),
            "filesize": os.path.getsize(os.getcwd()+"/lab4/data/"+filename+".json"),
            "time": end_time
        }])
        write_to_CSV(df)


def SHA256():
    """
    Input : path to file for hashing
    Output: SHA256 generated hash
    """
    filename = input("\nEnter the input filename to hash: ")
    start_time = time.time()

    sha256_hash = hashlib.sha256()
    with open(filename, "rb") as f:
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)

    end_time = time.time() - start_time
    print(f"SHA256 Hash for {filename} : ", sha256_hash.hexdigest())
    print(f"Completed in : {end_time} seconds.")


def main():
    print("Select Action:\n1. AES encryption/decryption\n2. RSA encryption/decryption\n3. RSA Signature\n4. SHA-256 Hashing\n5. Plot Data(if exists)")
    objType = int(input("Enter Option: "))
    if(objType == 1):
        print("Starting AES encryption/decryption ....")
        key = int(
            input("Pick one of the keylengths :\n1. 128\n2. 192\n3. 256\n"))
        if (key == 1):
            keylen = 16
        elif (key == 2):
            keylen = 24
        elif (key == 3):
            keylen = 32
        else:
            print("Only option 1 , 2 or 3 is accepted.")
            main()
        AES_(keylen)
    elif(objType == 2):
        print("Starting RSA encryption/decryption ....")
        key = int(
            input("Pick one of the keylengths :\n1. 1024\n2. 2048\n3. 4096\n"))
        if (key == 1):
            keylen = 1024
        elif (key == 2):
            keylen = 2048
        elif (key == 3):
            keylen = 4096
        else:
            print("Only option 1 , 2 or 3 is accepted.")
            main()
        RSA_(keylen)
    elif(objType == 3):
        print("RSA Signature")
    elif(objType == 4):
        SHA256()
    elif (objType == 5):
        logtype = int(input("Choose a logging type :\n1. AES\n2. RSA\n"))
        log = ""
        if(logtype == 1):
            log = "AES"
        elif(logtype == 2):
            log == "RSA"
        plot_data(log)


if __name__ == "__main__":
    main()
