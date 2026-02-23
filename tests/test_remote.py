"""Unit tests for HeadlessIda remote execution features.

NOTE: These tests mock out the remote connection and do not require
an actual IDA instance. Therefore, it can be less accurate.
"""
import unittest
from unittest.mock import MagicMock, patch


class TestRemoteEval(unittest.TestCase):
    """Tests for remote_eval functionality."""

    def setUp(self):
        """Set up mock connection for each test."""
        self.mock_conn = MagicMock()
        self.mock_root = MagicMock()
        self.mock_conn.root = self.mock_root

    def test_remote_eval_simple_expression(self):
        """Test remote_eval with a simple arithmetic expression."""
        from headless_ida_multi.client import HeadlessIda

        with patch.object(HeadlessIda, '__init__', lambda x, **kwargs: None):
            ida = HeadlessIda() # type: ignore
            ida.conn = self.mock_conn
            ida.cleaned_up = False

            self.mock_root.exposed_eval.return_value = 2
            result = ida.remote_eval("1+1")

            self.mock_root.exposed_eval.assert_called_once_with("1+1")
            self.assertEqual(result, 2)

    def test_remote_eval_no_connection(self):
        """Test remote_eval raises error when no connection."""
        from headless_ida_multi.client import HeadlessIda

        with patch.object(HeadlessIda, '__init__', lambda x, **kwargs: None):
            ida = HeadlessIda() # type: ignore
            ida.conn = None
            ida.cleaned_up = False

            with self.assertRaises(RuntimeError) as ctx:
                ida.remote_eval("1+1")
            self.assertIn("No remote connection", str(ctx.exception))


class TestRemoteExec(unittest.TestCase):
    """Tests for remote_exec functionality."""

    def setUp(self):
        """Set up mock connection for each test."""
        self.mock_conn = MagicMock()
        self.mock_root = MagicMock()
        self.mock_conn.root = self.mock_root

    def test_remote_exec_simple_statement(self):
        """Test remote_exec with a simple statement."""
        from headless_ida_multi.client import HeadlessIda

        with patch.object(HeadlessIda, '__init__', lambda x, **kwargs: None):
            ida = HeadlessIda() # type: ignore
            ida.conn = self.mock_conn
            ida.cleaned_up = False

            ida.remote_exec("x = 1")
            self.mock_root.exposed_exec.assert_called_once_with("x = 1")

    def test_remote_exec_no_connection(self):
        """Test remote_exec raises error when no connection."""
        from headless_ida_multi.client import HeadlessIda

        with patch.object(HeadlessIda, '__init__', lambda x, **kwargs: None):
            ida = HeadlessIda() # type: ignore
            ida.conn = None
            ida.cleaned_up = False

            with self.assertRaises(RuntimeError) as ctx:
                ida.remote_exec("x = 1")
            self.assertIn("No remote connection", str(ctx.exception))


class TestRemoteImport(unittest.TestCase):
    """Tests for remote_import functionality."""

    def setUp(self):
        """Set up mock connection for each test."""
        self.mock_conn = MagicMock()
        self.mock_root = MagicMock()
        self.mock_conn.root = self.mock_root

    def test_remote_import_module(self):
        """Test remote_import imports a module."""
        from headless_ida_multi.client import HeadlessIda

        with patch.object(HeadlessIda, '__init__', lambda x, **kwargs: None):
            ida = HeadlessIda() # type: ignore
            ida.conn = self.mock_conn
            ida.cleaned_up = False

            mock_module = MagicMock()
            self.mock_root.exposed_import.return_value = mock_module

            result = ida.remote_import("idautils")
            self.mock_root.exposed_import.assert_called_once_with("idautils")
            self.assertEqual(result, mock_module)

    def test_remote_import_no_connection(self):
        """Test remote_import raises error when no connection."""
        from headless_ida_multi.client import HeadlessIda

        with patch.object(HeadlessIda, '__init__', lambda x, **kwargs: None):
            ida = HeadlessIda() # type: ignore
            ida.conn = None
            ida.cleaned_up = False

            with self.assertRaises(RuntimeError) as ctx:
                ida.remote_import("idautils")
            self.assertIn("No remote connection", str(ctx.exception))


class TestRemoteify(unittest.TestCase):
    """Tests for remoteify functionality."""

    def setUp(self):
        """Set up mock connection for each test."""
        self.mock_conn = MagicMock()
        self.mock_root = MagicMock()
        self.mock_conn.root = self.mock_root

    def test_remoteify_function(self):
        """Test remoteify pushes a function to remote and returns handle."""
        from headless_ida_multi.client import HeadlessIda

        def sample_function():
            return 42

        with patch.object(HeadlessIda, '__init__', lambda x, **kwargs: None):
            ida = HeadlessIda() # type: ignore
            ida.conn = self.mock_conn
            ida.cleaned_up = False

            mock_remote_fn = MagicMock()
            self.mock_root.exposed_eval.return_value = mock_remote_fn

            result = ida.remoteify(sample_function)

            # Verify exec was called to define the function
            self.assertTrue(self.mock_root.exposed_exec.called)
            # Verify eval was called to retrieve the function handle
            self.assertTrue(self.mock_root.exposed_eval.called)
            self.assertEqual(result, mock_remote_fn)

    def test_remoteify_extracts_source(self):
        """Test remoteify correctly extracts function source."""
        from headless_ida_multi.client import HeadlessIda

        def my_test_func():
            x = 1
            return x + 1

        with patch.object(HeadlessIda, '__init__', lambda x, **kwargs: None):
            ida = HeadlessIda() # type: ignore
            ida.conn = self.mock_conn
            ida.cleaned_up = False

            ida.remoteify(my_test_func)

            # Check that the first exec call contains the function definition
            # (remoteify calls exec twice: once to define, once to cleanup)
            first_exec_call = self.mock_root.exposed_exec.call_args_list[0][0][0]
            self.assertIn("my_test_func", first_exec_call)
            self.assertIn("return x + 1", first_exec_call)


if __name__ == "__main__":
    unittest.main()
