
# ---------- Consts ---------- #

ALPHABET_SIZE = 26


# ---------- Classes ---------- #


class CaesarCypher:
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

    def encrypt(self, data: str) -> str:
        """
        Encrypt the given `data` using caesar cypher with the key bound to the
        current instance.

        :param data: Data to encrypt.
        :return: Data encrypted using caesar cypher.
        """
        return self._caesar(data, True)

    def decrypt(self, data: str) -> str:
        """
        Decrypt the given `data` using caesar cypher with the key bound to the
        current instance.

        :param data: Data to encrypt.
        :return: Data encrypted using caesar cypher.
        """
        return self._caesar(data, False)


# ---------- Main Entry Point ---------- #


def main():
    data = "Mtm is the BEST!"

    encryptor = CaesarCypher(3)

    encrypted = encryptor.encrypt(data)
    print(encrypted, encryptor.decrypt(encrypted))


if __name__ == '__main__':
    main()

