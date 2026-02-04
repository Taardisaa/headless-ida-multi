"""Unit tests for helper functions."""
import socket
import threading
import unittest

from headless_ida.helpers import find_free_port, PortAllocLock


class TestFindFreePort(unittest.TestCase):
    """Tests for find_free_port functionality."""

    def test_find_free_port_returns_valid_port(self):
        """Test that find_free_port returns a valid port number."""
        port = find_free_port()
        self.assertIsInstance(port, int)
        self.assertGreater(port, 0)
        self.assertLess(port, 65536)

    def test_find_free_port_is_actually_free(self):
        """Test that the returned port can be bound to."""
        port = find_free_port()

        # Try to bind to the port
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(('localhost', port))
            except OSError:
                self.fail(f"Port {port} returned by find_free_port is not actually free")

    def test_find_free_port_returns_different_ports(self):
        """Test that consecutive calls return different ports when previous is held."""
        ports = set()
        sockets = []

        try:
            for _ in range(5):
                port = find_free_port()
                # Bind to the port to hold it
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(('localhost', port))
                sockets.append(s)
                ports.add(port)

            # All ports should be unique
            self.assertEqual(len(ports), 5)
        finally:
            for s in sockets:
                s.close()


class TestPortAllocLock(unittest.TestCase):
    """Tests for PortAllocLock thread safety."""

    def test_port_alloc_lock_is_threading_lock(self):
        """Test that PortAllocLock is a proper threading lock."""
        self.assertIsInstance(PortAllocLock, type(threading.Lock()))

    def test_port_alloc_lock_can_be_acquired(self):
        """Test that PortAllocLock can be acquired and released."""
        acquired = PortAllocLock.acquire(blocking=False)
        self.assertTrue(acquired)
        PortAllocLock.release()

    def test_port_alloc_lock_context_manager(self):
        """Test that PortAllocLock works as context manager."""
        with PortAllocLock:
            # Lock should be held here
            self.assertFalse(PortAllocLock.acquire(blocking=False))
        # Lock should be released here
        self.assertTrue(PortAllocLock.acquire(blocking=False))
        PortAllocLock.release()

    def test_concurrent_port_allocation(self):
        """Test that concurrent port allocations don't collide."""
        ports = []
        errors = []

        def allocate_port():
            try:
                with PortAllocLock:
                    port = find_free_port()
                    # Hold the port briefly
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                        s.bind(('localhost', port))
                        ports.append(port)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=allocate_port) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0, f"Errors occurred: {errors}")
        self.assertEqual(len(ports), 10)


if __name__ == "__main__":
    unittest.main()
