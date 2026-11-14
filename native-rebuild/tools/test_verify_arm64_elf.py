import pathlib
import struct
import tempfile
import unittest

from verify_arm64_elf import verify


def elf(kind=3, machine=183, elf_class=2, endian=1):
    data = bytearray(128)
    data[:4] = bytes((0x7f, 0x45, 0x4c, 0x46))
    data[4] = elf_class
    data[5] = endian
    data[6] = 1
    struct.pack_into("<HH", data, 16, kind, machine)
    data[80] = 1
    return bytes(data)


class Arm64ElfValidatorTest(unittest.TestCase):
    def check(self, content, valid):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "libtest.so"
            path.write_bytes(content)
            if valid:
                verify(path)
            else:
                with self.assertRaises(ValueError):
                    verify(path)

    def test_valid_arm64_shared_object_header(self):
        self.check(elf(), True)

    def test_rejects_truncated_elf(self):
        self.check(elf()[:20], False)

    def test_rejects_wrong_architecture(self):
        self.check(elf(machine=62), False)

    def test_rejects_executable_instead_of_shared_object(self):
        self.check(elf(kind=2), False)

    def test_rejects_32_bit_elf(self):
        self.check(elf(elf_class=1), False)

    def test_rejects_non_elf(self):
        self.check(b"not an ELF", False)

    def test_rejects_empty_payload(self):
        self.check(elf()[:64] + bytes(64), False)


if __name__ == "__main__":
    unittest.main()
