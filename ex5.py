import json
import os
# ---------- Imports ---------- #

from typing import List, Dict, Union

# ---------- Consts ---------- #

ALPHABET_SIZE = ord("z") + 1 - ord("a")

# Config file consts.
CONFIG_FILENAME = "config.json"
CONFIG_KEY_TYPE = "type"
CONFIG_KEY_MODE = "mode"
CONFIG_KEY_KEY = "key"

CONFIG_TYPE_CAESAR = "Caesar"
CONFIG_TYPE_VIGENERE = "Vigenere"
CONFIG_MODE_ENCRYPT = "encrypt"
CONFIG_MODE_DECRYPT = "decrypt"

TXT_EXTENSION = ".txt"
ENC_EXTENSION = ".enc"

# ---------- Classes ---------- #


class CaesarCipher:
    def __init__(self, key):
        self._key = key

    def _caesar(self, data: str, encrypt: bool) -> str:
        """
        Inner implementation of caesar cypher, allowing either encryption or
        decryption. Decryption is performed by "encrypting" using the negative
        of the key.

        :param data: Data to encrypt.
        :param encrypt: True for encryption, False for decryption.
        :return: The encrypted/decrypted data.
        """
        result = ""

        for c in data:
            if not c.isalpha():
                result += c
                continue

            a_ascii = ord("A") if c.isupper() else ord("a")

            if encrypt:
                offset = ((ord(c) - a_ascii) + self._key) % 26
            else:
                offset = ((ord(c) - a_ascii) - self._key) % 26

            value = a_ascii + offset
            result += chr(value)

        return result

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt the given `data` using caesar cypher with the key bound to the
        current instance.

        :param plaintext: Data to encrypt.
        :return: Data encrypted using caesar cypher.
        """
        return self._caesar(plaintext, True)

    def decrypt(self, ciphertext: str) -> str:
        """
        Decrypt the given `data` using caesar cypher with the key bound to the
        current instance.

        :param ciphertext: Data to encrypt.
        :return: Data encrypted using caesar cypher.
        """
        return self._caesar(ciphertext, False)


class VigenereCipher:
    def __init__(self, keys: List[int]):
        self._caesar_encryptors = [CaesarCipher(key) for key in keys]

    def _vigenere(self, data: str, encrypt: bool) -> str:
        """
        Inner implementation of vigenere cypher, allowing either encryption or
        decryption.

        :param data: Data to encrypt.
        :param encrypt: True for encryption, False for decryption.
        :return: The encrypted/decrypted data.
        """
        result = ""

        count = 0

        for c in data:
            if not c.isalpha():
                result += c
                continue

            i = count % len(self._caesar_encryptors)

            if encrypt:
                result += self._caesar_encryptors[i].encrypt(c)
            else:
                result += self._caesar_encryptors[i].decrypt(c)

            count += 1

        return result

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt the given `data` using vigenere cypher with the keys bound to
        the current instance.

        :param plaintext: Data to encrypt.
        :return: Data encrypted using vigenere cypher.
        """
        return self._vigenere(plaintext, True)

    def decrypt(self, ciphertext: str) -> str:
        """
        Decrypt the given `data` using vigenere cypher with the keys bound to
        the current instance.

        :param ciphertext: Data to encrypt.
        :return: Data encrypted using vigenere cypher.
        """
        return self._vigenere(ciphertext, False)

# ---------- Functions ---------- #


def getVigenereFromStr(keyString: str) -> VigenereCipher:
    """
    Create a vigenere cipher object using a text-based key.
    Each character in the given key is mapped to a corresponding integer key by
    index in the alphabet.

    :param keyString: String to generate keys from.
    """
    keyString = keyString.lower()

    keys = [ord(c) - ord("a") for c in keyString if c.isalpha()]

    return VigenereCipher(keys)


def _get_ecnryptor_from_config(config: Dict[str, str]) -> Union[CaesarCipher, VigenereCipher]:
    """
    Create an appropriate encryptor instance based on the given configuration.

    :param config: Configuration dict for the encryption.
    """
    encryption_type = config[CONFIG_KEY_TYPE]
    encryption_key = config[CONFIG_KEY_KEY]

    if encryption_type == CONFIG_TYPE_CAESAR:
        return CaesarCipher(encryption_key)
    elif encryption_type == CONFIG_TYPE_VIGENERE:
        if isinstance(encryption_key, str):
            return getVigenereFromStr(encryption_key)
        elif isinstance(encryption_key, list):
            return VigenereCipher(encryption_key)
        else:
            raise TypeError("Encryption key for Vigenere cipher should be either list or str.")
    else:
        raise ValueError(f"Invalid encryption method, got {encryption_type}.")


def process_single_file(encryptor: Union[CaesarCipher, VigenereCipher], filepath: str, mode: str) -> None:
    """
    Process a single file for the encryption/decryption process.

    :param encryptor: Encryptor object.
    :param filepath: Path to the file to encrypt/decrypt.
    :param mode: "encrypt" for encryption, "decrypt" for decryption.
    :raise ValueError: In case of invalid enc/dec mode.
    """
    basename, ext = os.path.splitext(filepath)

    output_path = None
    result = None

    if mode == CONFIG_MODE_ENCRYPT:
        if ext.lower() == TXT_EXTENSION:
            output_path = f"{basename}{ENC_EXTENSION}"
            with open(filepath) as encrypted_file:
                result = encryptor.encrypt(encrypted_file.read())
    elif mode == CONFIG_MODE_DECRYPT:
        if ext.lower() == TXT_EXTENSION:
            output_path = f"{basename}{TXT_EXTENSION}"
            with open(filepath) as encrypted_file:
                result = encryptor.decrypt(encrypted_file.read())
    else:
        raise ValueError(f"Invalid encryption mode, got {mode}.")

    with open(output_path, "wt") as decrypted:
        decrypted.write(result)


def processDirectory(dir_path: str) -> None:
    config_path = os.path.join(dir_path, CONFIG_FILENAME)
    with open(config_path, "rt") as config_file:
        config = json.load(config_file)

    encryptor = _get_ecnryptor_from_config(config)
    mode = config[CONFIG_KEY_MODE]

    for filename in os.listdir(dir_path):
        filepath = os.path.join(dir_path, filename)
        process_single_file(encryptor, filepath, mode)
