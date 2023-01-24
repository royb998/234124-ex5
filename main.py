
# ---------- Imports ---------- #

from typing import List

# ---------- Consts ---------- #

ALPHABET_SIZE = 26


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


# ---------- Main Entry Point ---------- #


def main():
    data = "Mtm is the BEST!"

    encryptor = CaesarCipher(3)

    encrypted = encryptor.encrypt(data)
    print(encrypted, encryptor.decrypt(encrypted))

    vc = VigenereCipher([7, 8, 11, 13, -2, 4])
    encrypted = vc.encrypt("come to Rivendell!")
    print(encrypted, vc.decrypt(encrypted))


if __name__ == '__main__':
    main()

