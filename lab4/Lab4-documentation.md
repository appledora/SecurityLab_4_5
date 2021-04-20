# Lab 4 user manual

## `Folder Structure` :
```
.
├── Crypto.py
├── data
│   ├── ani1_cfb.json
│   ├── ani1_ecb.json
│   ├── ani2_cfb.json
│   ├── ani2_ecb.json
│   ├── ani3_cfb.json
│   ├── ani3_ecb.json
│   ├── obi1.bin
│   ├── obi2.bin
│   └── obi3.bin
├── ExecutionLog.csv
├── keys
│   ├── AESKey-16-1.bin
│   ├── AESKey-16-3.bin
│   ├── AESKey-24-1.bin
│   ├── AESKey-24-3.bin
│   ├── AESKey-32-1.bin
│   ├── AESKey-32-3.bin
│   ├── private-1024.pem
│   ├── private-2048.pem
│   ├── private-4096.pem
│   ├── public-1024.pem
│   ├── public-2048.pem
│   └── public-4096.pem
├── Lab4-documentation.md
├── plots
│   ├── aes_stuff-AES.png
│   └── RSA_logs.png
├── __pycache__
│   ├── Crypto.cpython-36.pyc
│   └── Crypto.cpython-38.pyc
└── sample.txt
```
#### `Crypto.py` :
The main code that handles all 4 crypto operations.
#### `data`
Contains encrypted data generated during crypto operations
#### `keys`
Contains keys generated during crypto operations
#### `plots`
Stores plot generated from the log file.
#### `ExecutionLog.csv`
Contains various statistics regarding the crypto operations.

## `Instructions for running code` :
```
$ cd /lab4

$ pip install -r requirements.txt

$ python `Crypto.py`
```
After running the script, follow the prompted instructions on the terminal to perform different crypto operations.

## `Sources` :
 [PyCryptodome Documentation]( https://pycryptodome.readthedocs.io/en/latest/src/).
