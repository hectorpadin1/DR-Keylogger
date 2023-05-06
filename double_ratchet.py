from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hmac import HMAC


ROOT_KEY = b'\xc0\x04\x1c\xa2cYK\x19!\xd3\xaa\xe7\x0e\x9b\xc5B'



class Ratchet():

    
    def __init__(self) -> None:
        self.__dh = dh.DHParameterNumbers(
            30319579638337206599189880271169371662216269522895032061800636063362652370386521748999869603876350173858476509508315061333031319387431068113733724173932665305186706173159904282187717522489145436398655197355888028365883191955733906806316708521435262142271185807028971986702661383271389112636133140333043016177434606105982485038416207435427228207547817954747644297969226725118394723098020561729474331989672961902908847586104084434958442566925538775180838961956560458925054296356746093572761686226707529860746944286190072960576287840780921455786981478481394825308688175324015155329900248346909691882510520598268372110343, 
            2
        ).parameters(default_backend())
        self.__dh_pk = self.__dh.generate_private_key()
        self.__PKCS7 = PKCS7(128)
        self.__KLEN = 80
        self.__TLEN = 32
    

    def pairComm(self, pub: dh.DHPublicKey) -> None:
        sh_keys = self.__shared_keys(self.__dh_pk, pub)
        self.__rk, self.__ck = self.__kdf_rk(ROOT_KEY, sh_keys)


    def getPublicKey(self) -> bytes:
        return self.__dh_pk.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).strip()


    def getChainKey(self) -> bytes:
        return self.__ck


    def getRootKey(self) -> bytes:
        return self.__rk
    

    def updateDH(self) -> None:
        self.__dh_pk = self.__dh.generate_private_key()


    def __shared_keys(self, private_key: dh.DHPrivateKey, public_key: dh.DHPublicKey) -> bytes:
        return private_key.exchange(public_key)


    def __kdf_rk(self, root_key: bytes, dh_output: bytes) -> bytes:
        hkdf = HKDF(
            algorithm=SHA256(),
            length=32,
            salt=b'\x00' * 32,
            info=b'None',
        ).derive(root_key + dh_output)
        # returns the rootkey and the chainkey
        return hkdf[:16], hkdf[16:]


    def __kdf_ck(self, key: bytes) -> bytes:
        hkdf = HKDF(
            algorithm=SHA256(),
            length=32,
            salt=b'\x00' * 32,
            info=b'None',
        ).derive(key)
        self.__ck = hkdf[:16]
        self.__mk = hkdf[16:]


    def __newKeys(self, key: bytes, info: bytes) -> bytes:
        derived_key = HKDF(
            algorithm=SHA256(),
            length=self.__KLEN,
            salt=b'\x00' * self.__KLEN,
            info=info,
        ).derive(key)
        return derived_key[:32], derived_key[32:64], derived_key[64:]


    def __hmac(self, key: bytes, data: bytes) -> bytes:
        hmac = HMAC(
            key, 
            SHA256(), 
            backend=default_backend()
        )
        hmac.update(data)
        return hmac.finalize()


    def __aes_enc(self, key: bytes, iv: bytes, plaintext: bytes):
        padder = self.__PKCS7.padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()
        aes = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        ).encryptor()
        return aes.update(padded_plaintext) + aes.finalize()


    def __aes_dec(self, key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
        aes = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        ).decryptor()
        padded_plaintext = aes.update(ciphertext) + aes.finalize()
        unpadder = self.__PKCS7.unpadder()
        return unpadder.update(padded_plaintext) + unpadder.finalize()


    def __enc(self, plaintext: bytes, key: bytes, associated_data: bytes) -> bytes:
        # Get the derived keys
        enc_key, auth_key, iv = self.__newKeys(key, b'None')
        # Encrypt the plaintext using AES-CBC with PKCS7 padding
        ciphertext = self.__aes_enc(enc_key, iv, plaintext)
        # Calculate the authentication tag
        tag = self.__hmac(auth_key, associated_data + ciphertext)
        # Return the ciphertext and the tag
        return ciphertext + tag


    def __dec(self, ciphertext: bytes, key: bytes, associated_data: bytes) -> bytes:
        # Get the derived keys
        dec_key, auth_key, iv = self.__newKeys(key, b'None')
        # Split the authentication tag from the ciphertext
        tag = ciphertext[-self.__TLEN:]
        ciphertext = ciphertext[:-self.__TLEN]
        # Verify the authentication tag
        calculated_tag = self.__hmac(auth_key, associated_data + ciphertext)
        if tag != calculated_tag:
            raise Exception(f'Invalid tag! Expected {tag.hex()}, got {calculated_tag.hex()}')
        # Decrypt the ciphertext using AES-CBC with PKCS7 padding
        return self.__aes_dec(dec_key, iv, ciphertext)


    def encrypt(self, message: str) -> bytes:
        self.__kdf_ck(self.__ck)
        return self.__enc(message.encode(), self.__mk, b'AES-256-CBC')
    

    def decrypt(self, ciphertext: bytes) -> str:
        self.__kdf_ck(self.__ck)
        plaintext = self.__dec(ciphertext, self.__mk, b'AES-256-CBC')
        return plaintext.decode()