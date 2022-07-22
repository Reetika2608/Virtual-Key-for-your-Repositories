""" FMC - Expressway TaaCrypto Wrapper """

import subprocess
from managementconnector.config.managementconnectorproperties import ManagementConnectorProperties


class TaaCryptoException(Exception):
    """ Raised on TaaCrypto Command Execution Failure """

    def __init__(self, message):
        super().__init__(message)

        # custom object to access error message
        self.error = message


class SystemCallException(Exception):
    """ Raised on Subprocess system call Failure """

    def __init__(self, message):
        super().__init__(message)

        # custom object to access error message
        self.error = message


def system_call(command):
    """ Subprocess System Call """
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE)
        output, error = process.communicate()
        decoded_output = output.decode().strip()
        return decoded_output
    except Exception:
        raise


def encrypt_with_system_key(input_string):
    """ Encrypt input using Expressway's Python and TaaCrypto """
    try:
        taacrypto_encrypt = ManagementConnectorProperties.TAA_CRYPTO_ENCRYPT
        encrypt_command = ["/bin/python", taacrypto_encrypt, "-input_string", input_string]
        encrypted_output = system_call(encrypt_command)
        if "failure" in encrypted_output.lower():
            raise TaaCryptoException(encrypted_output)
        return encrypted_output
    except Exception as e:
        raise SystemCallException(str(e))


def decrypt_with_system_key(input_string):
    """ Decrypt input using Expressway's Python and TaaCrypto """
    try:
        taacrypto_decrypt = ManagementConnectorProperties.TAA_CRYPTO_DECRYPT
        decrypt_command = ["/bin/python", taacrypto_decrypt, "-input_string", input_string]
        decrypted_output = system_call(decrypt_command)
        if "failure" in decrypted_output.lower():
            raise TaaCryptoException(decrypted_output)
        return decrypted_output
    except Exception as e:
        raise SystemCallException(str(e))
