from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidTag
import mnemonic

from hashlib import pbkdf2_hmac, sha3_256
from typing import Union
import binascii
import base64
import time
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
    EPIC_VERSION: float = 3.0
    ITERATIONS: int = 100
    U_SIZE: int = 32

    info: str = None
    seed: bytes = None
    mnemonics: str = None
    public_key: bytes = None
    tor_address: bytes = None
    encrypted_seed_data: dict = None

    def __init__(self,
                 seed: bytes = None,
                 password: str = '',
                 mnemonics: str = None,
                 encrypted_seed: dict = None):

        if seed:
            self.from_seed(seed=seed)

        elif mnemonics:
            self.from_mnemonic(mnemonics=mnemonics)

        elif encrypted_seed:
            self.from_encrypted_seed(password=password, encrypted_seed=encrypted_seed)

        else:
            self.new(password=password)

        self._info()

    @staticmethod
    def _valid_mnemonics(mnemonics):
        """
        Basic validation of mnemonics input
        """
        return len(mnemonics.split(' ')) in [12 or 24]

    @staticmethod
    def _str_to_bytes(data: str) -> bytes:
        """
        Get str, unhexlify and return bytes
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
        if isinstance(password, str):
            password = password.encode('utf-8')

        return pbkdf2_hmac("sha512", password,
                           salt, self.ITERATIONS, self.U_SIZE)

    def _encrypted_seed_to_file(self, path: str) -> None:
        """
        Save encrypted seed data to wallet seed file (JSON)
        :param path: str, directory and file name for wallet seed file
        """
        if not self.encrypted_seed_data:
            try:
                self._encrypt_seed()
            except Exception:
                raise Exception("Error: can not create wallet seed file")

        with open(path, 'w') as file:
            json.dump(self.encrypted_seed_data, file, indent=2)

    def _decrypt_seed(self, password: str, data: dict) -> [bytes, None]:
        """
        Decrypt encrypted seed data
        :param password: str,
        :param data: dict, keys: encrypted_seed, nonce, salt
        :return: bytes, decrypted seed
        """
        # Validate data dict
        if not isinstance(data, dict) or len(data) < 3:
            raise Exception('Invalid data to decrypt wallet seed')

        # Parse data dict from strings to bytes
        salt = self._str_to_bytes(data['salt'])
        nonce = self._str_to_bytes(data['nonce'])
        encrypted_seed = self._str_to_bytes(data['encrypted_seed'])

        try:
            # Decrypt seed with generated key and given nonce
            enc_key = self._generate_key(password, salt)
            cypher = ChaCha20Poly1305(enc_key)
            decrypted_seed = cypher.decrypt(nonce, encrypted_seed, associated_data=None)

        except InvalidTag:
            print('ERROR: Invalid password')
            return

        return decrypted_seed

    def _encrypt_seed(self, password: str = '') -> dict:
        """
        Generate encrypted seed and return it with nonce and salt
        :param password: str,
        :return: dict, encrypted seed, nonce and salt
        """
        # Generate random bytes for nonce and salt
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

    def _mnemonic_from_seed(self) -> None:
        """
        Generate mnemonics from seed
        """
        mnemonic_obj = mnemonic.Mnemonic("english")
        self.mnemonics = mnemonic_obj.to_mnemonic(self.seed)

    def _public_key_from_seed(self) -> None:
        """
        Generate key pair from seed and return PublicKey
        """
        key_pair = Ed25519PrivateKey.from_private_bytes(self.seed)
        self.public_key = key_pair.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
            )

    def _tor_address(self) -> None:
        """
        Generale TOR address from wallet public key
        """
        version = b"\x03"
        checksum = sha3_256(b".onion checksum" + self.public_key + version).digest()
        self.tor_address = base64.b32encode(self.public_key + checksum[0:2] + version).lower()

    def _info(self) -> None:
        """
        Generate wallet summary string
        """
        seed = f"Seed (PrivateKey): {self.seed_as_str()}"
        title = f"\n// Epic-Cash Wallet Summary:"
        mnemonics = f"Mnemonics: {self.mnemonics}"
        public_key = f"PublicKey: {self.public_key_as_str()}"
        tor_address = f"TOR Address: {self.tor_address_as_str()}\n"

        self.info = '\n'.join([title, seed, public_key, mnemonics, tor_address])

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

    def tor_address_as_str(self) -> str:
        """
        :return: str, TOR address as string
        """
        return self.tor_address.decode('utf-8')

    def new(self, password: str = ''):
        """
        Generate new seed and create new wallet instance
        :param password: string, optional (to encrypt seed)
        :return: wallet instance
        """
        seed = os.urandom(self.U_SIZE)
        self.from_seed(seed)
        self._encrypt_seed(password=password)

        return self

    def from_seed(self, seed: Union[bytes, str]):
        """
        Initialize new epic-wallet instance from seed (random_bytes, 32)
        :return: wallet instance
        """
        if isinstance(seed, str):
            try:
                seed = binascii.unhexlify(seed)
            except Exception as e:
                print(e)

        self.seed = seed
        self._mnemonic_from_seed()
        self._public_key_from_seed()
        self._tor_address()
        self._info()

        return self

    def from_encrypted_seed(self, password: str, encrypted_seed: dict):
        """
        Initialize new epic-wallet instance from previously encrypted seed
        :return: wallet instance
        """
        seed = self._decrypt_seed(password=password, data=encrypted_seed)

        if seed:
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
        seed = bytes(mnemonic_obj.to_entropy(mnemonics))
        self.from_seed(seed)

        return self

    def save_to_file(self, path: str = None):
        """
        Save wallet encrypted seed to file (JSON)
        :param path: str, optional path to wallet encrypted seed file
        """
        # Set current working directory as path if not provided
        if not path:
            path = os.getcwd()

        file_path = os.path.join(path, self.SEED_FILE_NAME)

        # Handle existing wallet.seed and make backup
        if os.path.isfile(file_path):
            print('Wallet seed file already exist in this directory, making backup..')
            backup_file_name = f"backup_{int(time.time())}_{self.SEED_FILE_NAME}"
            backup_path = os.path.join(path, backup_file_name)
            os.rename(file_path, backup_path)
            print(f'"{backup_file_name}" saved in {path}')

        self._encrypted_seed_to_file(path=file_path)
        print(f"Wallet seed file created successfully")
