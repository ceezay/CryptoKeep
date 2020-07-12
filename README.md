# CryptoKeep

With millions of megabytes of data transmitted every second through multiple communication process throughout the world¸ data security becomes one of the crucial domains of focus and the issues related to it are very much substantial when it comes to transmission of sensitive and confidential information. At any given point of time, no user can ever rely on the security of the medium of communication in presence of an adversary to avoid any breach. 
Therefore, sensitive data is stored or communicated locally or in cloud using cryptography techniques that scrambles the data in the file to make it unreadable for intruders. These file encryption techniques are specifically classified into symmetric and asymmetric key cryptography based on the requirement of secret keys needed to perform the encryption and decryption of files. Symmetric encryption uses one single key common for both sender and receiver to encrypt and decrypt files respectively. This technique is much faster and simpler. The bigger advantage is its capability to encrypt large data files. Asymmetric encryption uses a set of 2 keys – a public and a private key. The public key is used for encryption which is accessible by everyone and the private key is used for decryption which is available with the user only. This adds a layer of security at the cost of increased time and space complexity. This makes them unsuitable for large data files. 
The best-known symmetric algorithm AES [1] uses 256-bit keys to perform encryption whereas RSA [2] asymmetric algorithm uses 1024 bits keys. For parallel implementation AES algorithm runs in GCM [3] (Galois/Counter Mode) mode i.e. AES-GCM. Focusing on the speed and security, we often forget authenticity and how easy it is to forge duplicate or fake data. It can easily be fixed using digital signatures. But the selection of key to generate the signature has to be appropriate in order to remove data vulnerability. Therefore, we use SHA-256 [4] hashing algorithm for that purpose. 
In this project, one symmetric algorithm AES-GCM, one hashing algorithm SHA-256, and one asymmetric algorithm RSA have been used to facilitate a hybrid encryption system which has the advantages of all the algorithms in terms of speed, security, integrity and authentication to be used to securely store or transmit data over a local/cloud/server system. The whole encryption system is implemented in Java environment providing an introductory structure for future deployment.
