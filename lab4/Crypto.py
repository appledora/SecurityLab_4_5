from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES, PKCS1_OAEP
import time
import os
import pandas as pd
import matplotlib.pyplot as plt
import warnings
warnings.filterwarnings("ignore")


def write_to_CSV(df):
    if not os.path.isfile(os.getcwd()+'/lab4/ExecutionLog.csv'):
        df.to_csv(os.getcwd()+'/lab4/ExecutionLog.csv')
    else:  # else it exists so append without writing the header
        df.to_csv(os.getcwd()+'/lab4/ExecutionLog.csv', mode='a', header=False)


def plot_data(logtype):
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
        "/home/appledora/Documents/Security2/lab4/data/"+filename+".bin", "wb")
    recipient_key = RSA.import_key(
        open("/home/appledora/Documents/Security2/lab4/keys/public-"+str(keylen)+".pem").read())
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
        input("Choose one of the options:\n1. Encrypt Data\n2. Decrypt Data"))
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


def main():
    print("Select Action:\n1. AES encryption/decryption\n2. RSA encryption/decryption\n3. RSA Signature\n4. SHA-256 Hashing\n5. Plot Data(if exists)")
    objType = int(input())
    if(objType == 1):
        print("AES")
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
        print("SHA-256")
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
