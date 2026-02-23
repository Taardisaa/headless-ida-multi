"""Integration tests for idb_path parameter functionality.

NOTE: These tests require an actual IDA installation.
Set the IDA_DIR environment variable to your IDA installation path.
"""
import os
import tempfile
import unittest
from pathlib import Path


# Skip all tests if IDA_DIR is not set
IDA_DIR: str = os.environ.get("IDA_DIR", "")


@unittest.skipIf(not IDA_DIR, "IDA_DIR environment variable not set")
class TestIdbPath(unittest.TestCase):
    """Integration tests for idb_path parameter."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_binary = Path(__file__).parent / "testbin" / "foo"
        self.assertTrue(self.test_binary.exists(), f"Test binary not found: {self.test_binary}")

    def test_idb_path_creates_database_at_specified_location(self):
        """Test that specifying idb_path creates the database at that location."""
        from headless_ida_multi import HeadlessIda

        with tempfile.TemporaryDirectory() as tmpdir:
            idb_path = Path(tmpdir) / "output.i64"

            ida = HeadlessIda(
                ida_dir=IDA_DIR,
                binary_path=str(self.test_binary),
                idb_path=str(idb_path)
            )
            ida.clean_up()

            # The database should be created at the specified path
            self.assertTrue(idb_path.exists(), f"IDB file not created at {idb_path}")
            
        with tempfile.TemporaryDirectory() as tmpdir:
            ida = HeadlessIda(
                ida_dir=IDA_DIR,
                binary_path=str(self.test_binary),
            )
            ida.clean_up()

            # The database should be created at the specified path
            # NOTE: Since I don't have idalib, this part of the test is limited to checking the old version of IDA, 
            # e.g., IDA 8.4.
            self.assertTrue(ida.idb_path and not Path(ida.idb_path).exists(), "Temporary IDB file should be cleaned up")
            

    def test_idb_path_creates_nested_directories(self):
        """Test that idb_path creates parent directories if they don't exist."""
        from headless_ida_multi import HeadlessIda

        with tempfile.TemporaryDirectory() as tmpdir:
            idb_path = Path(tmpdir) / "subdir" / "nested" / "output.i64"

            # Verify parent directories don't exist yet
            self.assertFalse(idb_path.parent.exists())

            ida = HeadlessIda(
                ida_dir=IDA_DIR,
                binary_path=str(self.test_binary),
                idb_path=str(idb_path)
            )
            ida.clean_up()
            
            # The database should be created and parent dirs should exist
            self.assertTrue(idb_path.parent.exists(), "Parent directories not created")
            self.assertTrue(idb_path.exists(), f"IDB file not created at {idb_path}")


if __name__ == "__main__":
    unittest.main()
