from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import serialization
import mnemonic

from hashlib import pbkdf2_hmac, sha3_256
from typing import Union
import binascii
import base64
import json
import os


class WalletSeed:
    """
    Epic-Cash Wallet cryptography Python manager:

    create() -> Create completely new epic-wallet instance
    from_bytes() -> Initialize epic-wallet from seed (bytes)
    from_mnemonic() -> Initialize epic-wallet from mnemonic seed-phrase (str)
    from_encrypted_seed() -> Initialize epic-wallet from previously encrypted seed (dict)
    get_tor_address() -> Generate onion TOR address for epic-wallet listener
    seed_as_str() -> Return wallet seed as string

    """

    SEED_FILE_NAME = 'wallet.seed'
    ITERATIONS: int = 100
    U_SIZE: int = 32

    seed: bytes = None
    mnemonics: str = None
    public_key: bytes = None
    encrypted_seed_data: dict = None

    def __init__(self, seed: bytes = None):
        if seed:
            self.from_seed(seed=seed)

    @staticmethod
    def _valid_mnemonics(mnemonics):
        return len(mnemonics.split(' ')) in [12, 24]

    @staticmethod
    def _str_to_bytes(data: str) -> bytes:
        """
        Get bytes, hexlify them and return utf-8 decoded string
        """
        return binascii.unhexlify(data)

    @staticmethod
    def _bytes_to_str(data: bytes) -> str:
        """
        Get bytes hexlify them and return utf-8 decoded string
        """
        return binascii.hexlify(data).decode('utf-8')

    def _generate_key(self, password: str, salt: bytes):
        """
        Generate HMAC512 PrivateKey used to wallet encryption
        :param password: str
        :param salt: bytes
        :return: bytes, PrivateKey
        """
        return pbkdf2_hmac("sha512", password.encode('utf-8'),
                           salt, self.ITERATIONS, self.U_SIZE)

    def _seed_file_exists(self, directory: str) -> bool:
        """
        Check against already existing wallet seed file
        """
        file_path = os.path.join(directory, self.SEED_FILE_NAME)
        return os.path.isfile(file_path)

    def _encrypted_seed_to_file(self) -> None:
        """
        Save encrypted seed data to wallet seed file (JSON)
        """
        if self._seed_file_exists(directory=os.getcwd()):
            raise Exception('Seed file already exist')

        with open(self.SEED_FILE_NAME, 'w') as file:
            json.dump(self.encrypted_seed_data, file, indent=2)

    def _decrypt_seed(self, password: str, data: dict) -> bytes:
        """
        Read encrypted seed data (enc_seed, nonce, salt) and return seed
        :return: bytes, decrypted seed
        """
        assert isinstance(data, dict)

        # Decrypt seed with generated key and given nonce
        enc_key = self._generate_key(password, data['salt'])
        cypher = ChaCha20Poly1305(enc_key)
        decrypted_seed = cypher.decrypt(data['nonce'], data['encrypted_seed'], associated_data=None)
        return decrypted_seed

    def seed_as_str(self) -> str:
        """
        :return: str, seed bytes as string
        """
        return self._bytes_to_str(self.seed)

    def public_key_as_str(self) -> str:
        """
        :return: str, PublicKey byte data as string
        """
        return self._bytes_to_str(self.public_key)

    def _encrypt_seed(self, password: str) -> dict:
        """
        Generate encrypted seed and return it with nonce and salt
        :return: dict, encrypted seed, nonce and salt
        """
        nonce = os.urandom(12)
        salt = os.urandom(8)

        # Generate PrivateKey
        enc_key = self._generate_key(password, salt)

        # Encrypt seed with generated PrivateKey and nonce
        cypher = ChaCha20Poly1305(enc_key)
        encrypted_seed = cypher.encrypt(nonce, self.seed, associated_data=None)

        # Prepare data used later to decrypt seed
        self.encrypted_seed_data = {
            "encrypted_seed": self._bytes_to_str(encrypted_seed),
            "salt": self._bytes_to_str(salt),
            "nonce": self._bytes_to_str(nonce)
            }

        return self.encrypted_seed_data

    def _mnemonic_from_seed(self) -> str:
        """
        Generate mnemonics from seed
        :return: str, mnemonic seed-phrase
        """
        mnemonic_obj = mnemonic.Mnemonic("english")
        self.mnemonics = mnemonic_obj.to_mnemonic(self.seed)

        return self.mnemonics

    def _public_key_from_seed(self) -> bytes:
        """
        Generate key pair from seed and return PublicKey
        :return: bytes, PublicKey
        """
        key_pair = Ed25519PrivateKey.from_private_bytes(self.seed)
        self.public_key = key_pair.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
            )
        return self.public_key

    def create(self, password: str = ''):
        """
        Generate new seed and create new wallet instance
        :param password: string, optional (to encrypt seed)
        :return: wallet instance
        """
        seed = os.urandom(self.U_SIZE)
        self.from_seed(seed)
        self._encrypt_seed(password=password)
        # self._encrypted_seed_to_file()

        return self

    def from_seed(self, seed: Union[bytes, str]):
        """
        Initialize new epic-wallet instance from seed (random_bytes, 32)
        """
        if isinstance(seed, str):
            seed = binascii.unhexlify(seed)

        self.seed = seed
        self._mnemonic_from_seed()
        self._public_key_from_seed()
        return self

    def from_encrypted_seed(self, password: str, data: dict):
        """
        Initialize new epic-wallet instance from previously encrypted seed
        """
        seed = self._decrypt_seed(password=password, data=data)
        self.from_seed(seed)
        return self

    def from_mnemonic(self, mnemonics: Union[str, list]):
        """
        Create new wallet instance from mnemonic seed-phrase
        :param mnemonics: str or list, 12 or 14 words
        :return: wallet instance
        """
        if isinstance(mnemonics, list):
            mnemonics = ' '.join(mnemonics)

        if self._valid_mnemonics(mnemonics):
            raise Exception('Invalid mnemonics')

        mnemonic_obj = mnemonic.Mnemonic("english")
        seed = mnemonic_obj.to_seed(mnemonics)
        self.from_seed(seed)

        return self

    def get_tor_address(self):
        """
        Generale TOR address from wallet public key
        :return: str, TOR onion address
        """
        version = b"\x03"
        checksum = sha3_256(b".onion checksum" + self.public_key + version).digest()

        return base64.b32encode(self.public_key + checksum[0:2] + version).lower()


