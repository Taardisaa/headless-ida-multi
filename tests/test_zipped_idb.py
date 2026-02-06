"""Unit tests for zipped IDA database extraction."""
import os
import tempfile
import unittest
import zipfile
from pathlib import Path

from headless_ida.client import HeadlessIda


class _DummyIda:
    """Minimal stand-in so we can call _extract_zipped_idb without a full __init__."""
    _zip_temp_dir = None


class TestExtractZippedIdb(unittest.TestCase):
    """Tests for _extract_zipped_idb helper method."""

    def _call(self, binary_path):
        """Call _extract_zipped_idb on a dummy instance."""
        dummy = _DummyIda()
        result = HeadlessIda._extract_zipped_idb(dummy, binary_path)
        return dummy, result

    def test_non_zip_path_unchanged(self):
        """Non-zip paths are returned unchanged."""
        for suffix in ("/tmp/foo.elf", "/tmp/bar.idb", "/tmp/baz.i64", "/tmp/x.zip"):
            dummy, result = self._call(suffix)
            self.assertEqual(result, suffix)
            self.assertIsNone(dummy._zip_temp_dir)

    def test_extract_i64_zip(self):
        """A .i64.zip file is extracted and the .i64 path returned."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a fake .i64 file and zip it
            idb_name = "test_db.i64"
            idb_content = b"\x00" * 64
            zip_path = Path(tmpdir) / "test_db.i64.zip"
            with zipfile.ZipFile(zip_path, "w") as zf:
                zf.writestr(idb_name, idb_content)

            dummy, result = self._call(str(zip_path))

            self.assertIsNotNone(dummy._zip_temp_dir)
            self.assertTrue(Path(result).exists())
            self.assertTrue(result.endswith(".i64"))
            with open(result, "rb") as f:
                self.assertEqual(f.read(), idb_content)

            # Clean up the temp dir created by the method
            import shutil
            shutil.rmtree(dummy._zip_temp_dir, ignore_errors=True)

    def test_extract_idb_zip(self):
        """A .idb.zip file is extracted and the .idb path returned."""
        with tempfile.TemporaryDirectory() as tmpdir:
            idb_name = "sample.idb"
            idb_content = b"\xAB\xCD" * 32
            zip_path = Path(tmpdir) / "sample.idb.zip"
            with zipfile.ZipFile(zip_path, "w") as zf:
                zf.writestr(idb_name, idb_content)

            dummy, result = self._call(str(zip_path))

            self.assertIsNotNone(dummy._zip_temp_dir)
            self.assertTrue(Path(result).exists())
            self.assertTrue(result.endswith(".idb"))
            with open(result, "rb") as f:
                self.assertEqual(f.read(), idb_content)

            import shutil
            shutil.rmtree(dummy._zip_temp_dir, ignore_errors=True)

    def test_extract_nested_idb_in_zip(self):
        """An IDB nested inside a subdirectory in the zip is still found."""
        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = Path(tmpdir) / "nested.i64.zip"
            with zipfile.ZipFile(zip_path, "w") as zf:
                zf.writestr("subdir/deep.i64", b"\x01\x02\x03")

            dummy, result = self._call(str(zip_path))

            self.assertTrue(result.endswith(".i64"))
            self.assertTrue(Path(result).exists())

            import shutil
            shutil.rmtree(dummy._zip_temp_dir, ignore_errors=True)

    def test_raises_if_no_idb_in_zip(self):
        """ValueError is raised when the zip contains no .idb or .i64 file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = Path(tmpdir) / "empty.i64.zip"
            with zipfile.ZipFile(zip_path, "w") as zf:
                zf.writestr("readme.txt", "not a database")

            with self.assertRaises(ValueError):
                self._call(str(zip_path))

    def test_path_object_input(self):
        """binary_path passed as a Path object works correctly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = Path(tmpdir) / "pathobj.i64.zip"
            with zipfile.ZipFile(zip_path, "w") as zf:
                zf.writestr("db.i64", b"\x00")

            dummy, result = self._call(zip_path)  # Pass Path, not str

            self.assertTrue(Path(result).exists())
            self.assertTrue(result.endswith(".i64"))

            import shutil
            shutil.rmtree(dummy._zip_temp_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
