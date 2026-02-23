"""Unit tests for helper functions."""
import multiprocessing
import socket
import time
import threading
import unittest

from headless_ida_multi.helpers import find_free_port, PortAllocLock


# Top-level functions for multiprocessing (must be picklable)

def _hold_lock_in_process(result_list, proc_id):
    """Acquire the lock, record enter/exit timestamps."""
    from headless_ida_multi.helpers import PortAllocLock
    import time
    with PortAllocLock:
        result_list.append(('enter', proc_id, time.monotonic()))
        time.sleep(0.1)
        result_list.append(('exit', proc_id, time.monotonic()))


def _allocate_port_in_process(port_list, error_list):
    """Allocate a port under the lock in a subprocess."""
    from headless_ida_multi.helpers import PortAllocLock, find_free_port
    import socket
    try:
        with PortAllocLock:
            port = find_free_port()
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(('localhost', port))
                port_list.append(port)
    except Exception as e:
        error_list.append(str(e))


def _increment_shared_counter(counter, n_increments):
    """Increment a shared counter n times under the lock.

    Classic lock correctness test: without proper serialization,
    read-modify-write on the shared value loses increments.
    """
    from headless_ida_multi.helpers import PortAllocLock
    for _ in range(n_increments):
        with PortAllocLock:
            counter.value += 1


def _allocate_ports_burst(port_list, error_list, n_ports):
    """Allocate multiple ports in rapid succession under the lock."""
    from headless_ida_multi.helpers import PortAllocLock, find_free_port
    import socket
    for _ in range(n_ports):
        try:
            with PortAllocLock:
                port = find_free_port()
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    s.bind(('localhost', port))
                    port_list.append(port)
        except Exception as e:
            error_list.append(str(e))


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
    """Tests for PortAllocLock cross-process file lock."""

    def test_port_alloc_lock_is_context_manager(self):
        """Test that PortAllocLock supports the context manager protocol."""
        self.assertTrue(hasattr(PortAllocLock, '__enter__'))
        self.assertTrue(hasattr(PortAllocLock, '__exit__'))

    def test_port_alloc_lock_can_be_entered_and_exited(self):
        """Test that PortAllocLock can be acquired and released."""
        with PortAllocLock:
            pass  # should not raise

    def test_port_alloc_lock_serializes_threads(self):
        """Test that PortAllocLock serializes access across threads."""
        order = []

        def hold_lock(thread_id):
            with PortAllocLock:
                order.append(('enter', thread_id))
                import time
                time.sleep(0.05)
                order.append(('exit', thread_id))

        t1 = threading.Thread(target=hold_lock, args=(1,))
        t2 = threading.Thread(target=hold_lock, args=(2,))
        t1.start()
        import time
        time.sleep(0.01)  # give t1 a head start
        t2.start()
        t1.join()
        t2.join()

        # The enters/exits should not interleave: one thread must fully
        # complete before the other enters.
        self.assertEqual(order[0][0], 'enter')
        self.assertEqual(order[1][0], 'exit')
        self.assertEqual(order[0][1], order[1][1])  # same thread

    def test_concurrent_port_allocation(self):
        """Test that concurrent port allocations don't collide."""
        ports = []
        errors = []

        def allocate_port():
            try:
                with PortAllocLock:
                    port = find_free_port()
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


class TestPortAllocLockMultiProcess(unittest.TestCase):
    """Tests for PortAllocLock cross-process serialization."""

    def test_lock_serializes_across_processes(self):
        """Test that PortAllocLock serializes access across separate processes."""
        manager = multiprocessing.Manager()
        results = manager.list()

        p1 = multiprocessing.Process(target=_hold_lock_in_process, args=(results, 1))
        p2 = multiprocessing.Process(target=_hold_lock_in_process, args=(results, 2))

        p1.start()
        time.sleep(0.02)  # give p1 a head start to acquire first
        p2.start()
        p1.join()
        p2.join()

        events = list(results)
        self.assertEqual(len(events), 4)
        # No interleaving: enter/exit of one process must be adjacent
        self.assertEqual(events[0][0], 'enter')
        self.assertEqual(events[1][0], 'exit')
        self.assertEqual(events[0][1], events[1][1])  # same process completed fully

    def test_concurrent_port_allocation_across_processes(self):
        """Test that port allocations across processes don't collide."""
        manager = multiprocessing.Manager()
        ports = manager.list()
        errors = manager.list()

        procs = [
            multiprocessing.Process(target=_allocate_port_in_process, args=(ports, errors))
            for _ in range(10)
        ]
        for p in procs:
            p.start()
        for p in procs:
            p.join()

        self.assertEqual(len(errors), 0, f"Errors occurred: {list(errors)}")
        self.assertEqual(len(ports), 10)


class TestPortAllocLockStress(unittest.TestCase):
    """Stress tests for PortAllocLock under high contention."""

    NUM_PROCS = 20
    INCREMENTS_PER_PROC = 50

    def test_shared_counter_integrity(self):
        """Classic lock correctness: N processes x M increments must equal N*M.

        Without proper cross-process serialization, concurrent read-modify-write
        on a shared counter will lose increments.
        """
        counter = multiprocessing.Value('i', 0)

        procs = [
            multiprocessing.Process(
                target=_increment_shared_counter,
                args=(counter, self.INCREMENTS_PER_PROC),
            )
            for _ in range(self.NUM_PROCS)
        ]
        for p in procs:
            p.start()
        for p in procs:
            p.join()

        expected = self.NUM_PROCS * self.INCREMENTS_PER_PROC
        self.assertEqual(
            counter.value, expected,
            f"Lost increments: expected {expected}, got {counter.value} "
            f"({expected - counter.value} lost)"
        )

    def test_no_interleaving_under_high_contention(self):
        """Verify enter/exit pairs never interleave across many processes."""
        manager = multiprocessing.Manager()
        results = manager.list()

        procs = [
            multiprocessing.Process(
                target=_hold_lock_in_process,
                args=(results, i),
            )
            for i in range(self.NUM_PROCS)
        ]
        for p in procs:
            p.start()
        for p in procs:
            p.join()

        events = list(results)
        self.assertEqual(len(events), self.NUM_PROCS * 2)

        # Walk events pairwise: every (enter, exit) must be from the same process
        for i in range(0, len(events), 2):
            self.assertEqual(events[i][0], 'enter', f"Event {i}: expected enter")
            self.assertEqual(events[i+1][0], 'exit', f"Event {i+1}: expected exit")
            self.assertEqual(
                events[i][1], events[i+1][1],
                f"Interleaving detected: enter from proc {events[i][1]}, "
                f"exit from proc {events[i+1][1]}"
            )
            # exit timestamp must be after enter timestamp
            self.assertGreater(events[i+1][2], events[i][2])

    def test_port_allocation_burst_across_processes(self):
        """Many processes each allocating multiple ports in rapid fire."""
        n_ports_per_proc = 5
        manager = multiprocessing.Manager()
        ports = manager.list()
        errors = manager.list()

        procs = [
            multiprocessing.Process(
                target=_allocate_ports_burst,
                args=(ports, errors, n_ports_per_proc),
            )
            for _ in range(self.NUM_PROCS)
        ]
        for p in procs:
            p.start()
        for p in procs:
            p.join()

        expected_total = self.NUM_PROCS * n_ports_per_proc
        self.assertEqual(len(errors), 0, f"Errors occurred: {list(errors)}")
        self.assertEqual(len(ports), expected_total)


if __name__ == "__main__":
    unittest.main()
