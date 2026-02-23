"""
A copy of ida_script.py that keeps the database on exit.
"""

import rpyc
import importlib
import ida_auto # type: ignore
import ida_loader   # type: ignore
import ida_pro  # type: ignore
import idc  # type: ignore
import sys
from rpyc.utils.server import OneShotServer

class HeadlessIda(rpyc.Service):
    """
    HeadlessIda

    A headless IDA Pro service that provides remote procedure call (RPC) capabilities
    via rpyc (Remote Python Call).

    This class manages the lifecycle of a headless IDA Pro instance, handling connections,
    disconnections, and providing remote module importing functionality.

    Attributes:
        Inherits from rpyc.Service for RPC server capabilities.

    Methods:
        __init__(): Initializes the HeadlessIda service and waits for IDA auto-analysis to complete.
        
        on_connect(conn): Handles client connection by setting up database flags and redirecting
            standard output/error streams to the client.
        
        on_disconnect(conn): Handles client disconnection by exiting IDA Pro and restoring
            standard output/error streams.
        
        exposed_import_module(mod): Remote method to import a Python module by name and return it.
    """
    def __init__(self):
        super().__init__()
        # Wait for auto analysis to complete
        ida_auto.auto_wait()

    def on_connect(self, conn):
        # Note: DBFL_KILL is not set, so the database is preserved on exit.
        # Cleanup of temp databases is handled by the client.
        # ida_loader.set_database_flags(ida_loader.DBFL_KILL)
        sys.stdout.write = conn.root.stdout_write
        sys.stderr.write = conn.root.stderr_write

    def on_disconnect(self, conn):
        ida_pro.qexit(0)
        sys.stdout = sys.__stdout__
        sys.stderr = sys.__stderr__

    def exposed_import_module(self, mod):
        return importlib.import_module(mod)
    
    ### Added by Taardis
    def exposed_get_idc_argv(self):
        return idc.ARGV
    
    def exposed_import(self, module_name: str):
        return importlib.import_module(module_name)
    
    def exposed_eval(self, eval_string: str):
        """WARNING: Using eval can be dangerous if the input is not controlled."""
        return eval(eval_string)
    
    def exposed_exec(self, exec_string: str):
        """WARNING: Using exec can be dangerous if the input is not controlled."""
        exec(exec_string)

        



if __name__ == "__main__":
    t = OneShotServer(
        HeadlessIda,
        port=int(idc.ARGV[1]), 
        protocol_config={"allow_all_attrs": True})
    t.start()
    pass
