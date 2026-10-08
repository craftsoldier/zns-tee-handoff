"""Check that archive identity is independent of source filesystem metadata."""
import os
from pathlib import Path
import tempfile
import unittest
from build import pack


class ArchiveTests(unittest.TestCase):
    def test_timestamp_and_creation_order_do_not_change_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first, second = root / "a", root / "b"
            first.mkdir()
            second.mkdir()
            for stage, order, timestamp in ((first, ("x", "y"), 100), (second, ("y", "x"), 200)):
                for name in order:
                    path = stage / name
                    path.write_bytes(name.encode())
                    os.utime(path, (timestamp, timestamp))
                (stage / "link").symlink_to("x")
            self.assertEqual(pack(first), pack(second))
            (second / "x").write_bytes(b"changed")
            self.assertNotEqual(pack(first), pack(second))


if __name__ == "__main__":
    unittest.main()
