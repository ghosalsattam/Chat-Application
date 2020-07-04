from Crypto.PublicKey import RSA

from Crypto.Random import new


class RSA_Cipher:
    """
    This class generates the public and private key of the RSA code.
    """

    def generate_key(self, key_length):
        "Generate private and public key for RSA encrypting."
        random_generator = new().read
        self.private_key = RSA.generate(1024, random_generator)
        self.public_key = self.private_key.publickey()
        self.pk = self.public_key.exportKey()
