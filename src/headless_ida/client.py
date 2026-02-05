import atexit
import builtins
import ctypes
import os
import shutil
import site
import socket
import subprocess
import sys
import importlib
import tempfile
from typing import Optional, Union, Any, Dict, List, Tuple
from pathlib import Path
import inspect
import random
import textwrap
import time
import types

import rpyc

from .helpers import ForwardIO, IDABackendType, escape_path, resolve_ida_path, \
    find_free_port, PortAllocLock

class HeadlessIda:
    # Modules to override import for
    IDA_MODULES = [
        "ida_allins",
        "ida_auto",
        "ida_bitrange",
        "ida_bytes",
        "ida_dbg",
        "ida_dirtree",
        "ida_diskio",
        "ida_entry",
        "ida_enum",
        "ida_expr",
        "ida_fixup",
        "ida_fpro",
        "ida_frame",
        "ida_funcs",
        "ida_gdl",
        "ida_graph",
        "ida_hexrays",
        "ida_ida",
        "ida_idaapi",
        "ida_idc",
        "ida_idd",
        "ida_idp",
        "ida_ieee",
        "ida_kernwin",
        "ida_lines",
        "ida_loader",
        "ida_merge",
        "ida_mergemod",
        "ida_moves",
        "ida_nalt",
        "ida_name",
        "ida_netnode",
        "ida_offset",
        "ida_pro",
        "ida_problems",
        "ida_range",
        "ida_registry",
        "ida_search",
        "ida_segment",
        "ida_segregs",
        "ida_srclang",
        "ida_strlist",
        "ida_struct",
        "ida_tryblks",
        "ida_typeinf",
        "ida_ua",
        "ida_xref",
        "idc",
        "idautils",
        "idaapi",
    ]

    def __init__(
        self,
        ida_dir: Union[str, Path],
        binary_path: Union[str, Path],
        override_import: bool = True,
        port: Optional[int] = None,
        bits: int = 64,
        ftype: Optional[str] = None,
        processor: Optional[str] = None,
        idb_path: Optional[Union[str, Path]] = None,
    ) -> None:
        """
        Initialize a HeadlessIda instance.

        Args:
            ida_dir (Union[str, Path]): Path to IDA Pro installation directory.
            binary_path (Union[str, Path]): Path to the binary file to analyze.
            override_import (bool, optional): Whether to override the import mechanism for IDA modules. Defaults to True.
            port (Optional[int], optional): Port number for the IDA server. Defaults to 8000.
            bits (int, optional): Bitness of IDA Pro (32 or 64). Defaults to 64.
            ftype (Optional[str], optional): File type prefix for interpreting the input file. Defaults to None.
            processor (Optional[str], optional): Processor type. Defaults to None.
            idb_path (Optional[Union[str, Path]], optional): Path to store the IDA database (.idb/.i64).
                If None, uses a temporary directory. Defaults to None.
        """
        self.backend_type, self.ida_path = resolve_ida_path(ida_dir, bits)
        self.cleaned_up: bool = False
        # Register cleanup function
        # TODO: can refactor into __enter__/__exit__ for context manager support
        atexit.register(self.clean_up)

        self.idb_path = None
        self.conn = None

        if self.backend_type == IDABackendType.IDALIB:
            return self._idalib_backend(
                self.ida_path, binary_path, override_import, ftype=ftype, processor=processor,
                idb_path=idb_path
            )
        elif self.backend_type in [IDABackendType.IDA, IDABackendType.IDAT]:
            return self._ida_backend(
                idat_path=self.ida_path,
                binary_path=binary_path,
                override_import=override_import,
                port=port,
                ftype=ftype,
                processor=processor,
                idb_path=idb_path
            )

    def _idalib_backend(
        self,
        idalib_path: Union[str, Path],
        binary_path: Union[str, Path],
        override_import: bool = True,   # not used currently
        ftype: Optional[str] = None,
        processor: Optional[str] = None,
        idb_path: Optional[Union[str, Path]] = None,
    ):
        """
        Initialize IDA using the idalib library.

        Args:
            idalib_path (Union[str, Path]): Path to the idalib shared library.
            binary_path (Union[str, Path]): Path to the binary file to analyze.
            override_import (bool, optional): Not used currently. Defaults to True.
            ftype (Optional[str], optional): File type prefix for interpreting the input file. Defaults to None.
            processor (Optional[str], optional): Processor type. Defaults to None.
            idb_path (Optional[Union[str, Path]], optional): Path to store the IDA database.
                If None, uses a temporary directory. Defaults to None.
        """
        self.libida = ctypes.cdll.LoadLibrary(str(idalib_path))
        self.libida.init_library(0, None)

        # check if get_library_version is available
        if not hasattr(self.libida, "get_library_version"):
            major, minor, build = 9, 0, 0
        else:
            major, minor, build = ctypes.c_int(), ctypes.c_int(), ctypes.c_int()
            self.libida.get_library_version(
                ctypes.byref(major), ctypes.byref(minor), ctypes.byref(build)
            )
            major, minor, build = major.value, minor.value, build.value

        if major == 9 and minor == 0:
            sys.path.insert(
                0, os.path.join(os.path.dirname(idalib_path), "python/3/ida_64")
            )
            sys.path.insert(1, os.path.join(os.path.dirname(idalib_path), "python/3"))
        else:
            sys.path.insert(
                0, os.path.join(os.path.dirname(idalib_path), "python/lib-dynload")
            )
            sys.path.insert(1, os.path.join(os.path.dirname(idalib_path), "python"))

        # idalib creates the database next to the input file, so we copy the binary to the target location
        if idb_path is not None:
            idb_path = Path(idb_path)
            try:
                if not idb_path.parent.is_dir():
                    idb_path.parent.mkdir(parents=True, exist_ok=True)
            except OSError:
                raise ValueError(f"Failed to create directory for IDB path: {idb_path.parent}")
            # IDA will create .i64/.idb next to the binary, so we use the idb_path stem as the binary name
            target_file = str(idb_path.with_suffix(''))
            shutil.copy(binary_path, target_file)
            self.idb_path = str(idb_path)
        else:
            tempdir = tempfile.mkdtemp()
            shutil.copy(binary_path, tempdir)
            target_file = os.path.join(tempdir, os.path.basename(binary_path))
            # NOTE: the exact suffix of the database depends on the binary type, we can't set it here
            self.idb_path = None  # unknown at this point

        if major == 9 and minor == 0:
            self.libida.open_database(
                str(target_file).encode(),
                True,
            )
        else:
            ida_args = []
            if processor is not None:
                ida_args.append(f'-p{processor}')
            if ftype is not None:
                ida_args.append(f'-T{ftype}')
            if ida_args:
                cmd_line = ' '.join(ida_args)
                self.libida.open_database(
                    str(target_file).encode(),
                    True,
                    cmd_line.encode(),
                )
            else:
                self.libida.open_database(
                    str(target_file).encode(),
                    True,
                    None,
                )

    def _ida_backend(
        self,
        idat_path: Union[str, Path],
        binary_path: Union[str, Path],
        override_import: bool = True,
        port: Optional[int] = None,
        ftype: Optional[str] = None,
        processor: Optional[str] = None,
        idb_path: Optional[Union[str, Path]] = None,
    ) -> None:
        """
        Initialize IDA using `idat`.

        Args:
            idat_path (Union[str, Path]): Path to IDA Pro TUI executable.
            binary_path (Union[str, Path]): Path to the binary file to analyze.
            override_import (bool, optional): Whether to override the import mechanism for IDA modules. Defaults to True.
            port (Optional[int], optional): Port number for the IDA server. Defaults to None.
            ftype (Optional[str], optional): File type prefix for interpreting the input file. Defaults to None.
            processor (Optional[str], optional): Processor type. Defaults to None.
            idb_path (Optional[Union[str, Path]], optional): Path to store the IDA database (.idb/.i64).
                If None, uses a temporary file. Defaults to None.
        """
        server_path = os.path.join(
            os.path.realpath(os.path.dirname(__file__)), "ida_script.py"
        )
        server_with_db_path = os.path.join(
            os.path.realpath(os.path.dirname(__file__)), "ida_script_keep_db.py"
        )

        os.environ["PYTHONPATH"] = (
            os.pathsep.join(site.getsitepackages() + [site.getusersitepackages()])
            + os.pathsep
            + os.environ.get("PYTHONPATH", "")
        )

        # --- Port-independent setup (done once) ---
        is_idb_input = Path(binary_path).suffix in [".i64", ".idb"]
        if is_idb_input:
            tempidb = tempfile.NamedTemporaryFile(suffix=Path(binary_path).suffix)
            with open(binary_path, "rb") as f:
                tempidb.write(f.read())
            tempidb.flush()
            binary_path = tempidb.name
        else:
            if idb_path is not None:
                idb_path = Path(idb_path)
                if not idb_path.parent.is_dir():
                    try:
                        idb_path.parent.mkdir(parents=True, exist_ok=True)
                    except OSError:
                        raise ValueError(f"Failed to create directory for IDB path: {idb_path.parent}")
                output_path = str(idb_path)
            else:
                tempdir = tempfile.mkdtemp()
                output_path = os.path.join(tempdir, "database")
            self.idb_path = output_path

        # --- Retry loop: allocate port, launch IDA, connect ---
        # If an external process steals the ephemeral port between find_free_port()
        # and IDA binding to it, we retry with a new port and jittered backoff.
        user_port = port
        # If `port` is specified, we only try once since.
        max_retries = 1 if user_port is not None else 5 
        for attempt in range(max_retries):
            self.conn = None

            with PortAllocLock:
                port = user_port if user_port is not None else find_free_port()

                if is_idb_input:
                    command = f'"{idat_path}" -A -S"{escape_path(server_path)} {port}" -P+'
                    if ftype is not None:
                        command += f' -T "{ftype}"'
                    if processor is not None:
                        command += f' -p{processor}'
                    command += f' "{binary_path}"'
                else:
                    if idb_path is not None:
                        command = f'"{idat_path}" -o"{output_path}" -A -S"{escape_path(server_with_db_path)} {port}"'
                    else:
                        command = f'"{idat_path}" -o"{output_path}" -A -S"{escape_path(server_path)} {port}"'
                    if ftype is not None:
                        command += f' -T "{ftype}"'
                    if processor is not None:
                        command += f' -p{processor}'
                    command += f' "{binary_path}"'

                self.proc = subprocess.Popen(
                    command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                )

            # Wait for IDA to start its rpyc server
            while True:
                poll_code = self.proc.poll()
                if poll_code is not None:
                    # IDA exited prematurely (port may have been stolen)
                    break
                try:
                    self.conn = rpyc.connect(
                        "localhost",
                        port,
                        service=ForwardIO,  # type: ignore
                        config={"sync_request_timeout": 60 * 60 * 24},
                    )
                except Exception:
                    self.conn = None
                    continue
                break

            if self.conn is not None:
                break

            # Jittered exponential backoff before retrying
            if attempt < max_retries - 1:
                time.sleep(random.uniform(0, min(1.0, 0.1 * (2 ** attempt))))

        if self.conn is None:
            raise Exception(
                f"IDA failed to start after {max_retries} attempt(s): return code {self.proc.poll()}\n"
                f"Command: {command}\n"
                f"=============== STDOUT ===============\n{self.proc.stdout.read().decode() if self.proc.stdout else ''}\n"
                f"=============== STDERR ===============\n{self.proc.stderr.read().decode() if self.proc.stderr else ''}\n"
            )

        if override_import:
            self.override_import()

    def override_import(self):
        """
        Override the built-in import function to redirect IDA-specific module imports.
        
        This method replaces the standard Python import mechanism with a custom import handler
        that intercepts imports of IDA modules and routes them through the client's custom
        import_module method. Non-IDA modules are imported using the original import function.
        
        The override persists for the lifetime of the Python session and affects all subsequent
        import statements and __import__() calls.
        
        Raises:
            AttributeError: If the instance lacks the required IDA_MODULES attribute or import_module method.
        """
        original_import = builtins.__import__

        def ida_import(name, *args, **kwargs):
            if name in self.IDA_MODULES:
                return self.import_module(name)
            return original_import(name, *args, **kwargs)

        builtins.__import__ = ida_import

    def import_module(self, mod):
        """
        Import a module using the appropriate backend.

        This method attempts to import a Python module using either the local IDA library
        or a remote IDA connection. It first checks if a local libida instance is available,
        then falls back to a remote connection via rpyc, and raises an error if neither is available.

        Args:
            mod (str): The name of the module to import (e.g., 'os', 'json').

        Returns:
            module: The imported module object.

        Raises:
            RuntimeError: If neither a local libida instance nor a remote connection is initialized.
        """
        if hasattr(self, "libida"):
            return importlib.import_module(mod)
        if hasattr(self, "conn"):
            return self.conn.root.import_module(mod) if self.conn is not None else None
        else:
            raise RuntimeError("No IDA backend initialized")

    def clean_up(self, timeout: int = 10):
        """
        Clean up resources by closing the IDA database and connection.

        This method ensures that the IDA library database and network connection
        are properly closed. It uses a flag to prevent multiple cleanup attempts.

        If cleanup has already been performed, this method returns early.
        Otherwise, it closes the libida database (if available) and the connection
        (if available) before setting the cleaned_up flag to True.
        """
        if self.cleaned_up:
            return
        if hasattr(self, "libida"):
            self.libida.close_database(True)
        if self.conn:
            self.conn.close()
        # Wait for IDA process to fully exit (ensures database is saved)
        if hasattr(self, "proc"):
            self.proc.wait(timeout=timeout)
        self.cleaned_up = True

    def remote_import(self, module_name: str):
        if self.conn:
            return self.conn.root.exposed_import(module_name)
        else:
            raise RuntimeError("No remote connection established")

    def remote_eval(self, eval_string: str):
        if self.conn:
            return self.conn.root.exposed_eval(eval_string)
        else:
            raise RuntimeError("No remote connection established")

    def remote_exec(self, exec_string: str):
        if self.conn:
            self.conn.root.exposed_exec(exec_string)
        else:
            raise RuntimeError("No remote connection established")

    def remoteify(self, module_class_or_function, **kwargs):
        ### Copied from jfx_bridge/bridge: https://github.com/justfoxing/jfx_bridge
        """Push a module, class or function definition into the remote python interpreter, and return a handle to it.

        Notes:
            * requires that the class or function code is able to be understood by the remote interpreter (e.g., if it's running python2, the source must be python2 compatible)
            * If remoteify-ing a class, the class can't be defined in a REPL (a limitation of inspect.getsource). You need to define it in a file somewhere.
            * If remoteify-ing a module, it can't do relative imports - they require a package structure which won't exist
            * If remoteify-ing a module, you only get the handle back - it's not installed into the remote or local sys.modules, you need to do that yourself.
            * You can't remoteify a decorated function/class - it'll only get the source for the decorator wrapper, not the original.
        """
        source_string = inspect.getsource(module_class_or_function)
        name = module_class_or_function.__name__

        # random name that'll appear in the __main__ globals to retrieve the remote definition.
        # Used to avoid colliding with other uses of the name that might be there, or other clients
        temp_name = "_bridge_remoteify_temp_result" + "".join(
            [random.choice("0123456789ABCDEF") for _ in range(0, 8)]
        )

        if isinstance(module_class_or_function, types.ModuleType):
            """Modules need a bit of extra love and care."""
            # We'll use the temp_name to store the source of the module (makes it easier than patching it into the format string below and escaping everything),
            # and pass it as a global to the exec
            kwargs[temp_name] = source_string

            # We create a new module context to execute the module code in, then run a second exec from
            # the first exec inside the new module's __dict__, so imports are set correctly as globals of the module (not globals of the exec)
            # Note that we need to force the module name to be a string - python2 doesn't support unicode module names
            source_string = "import types\nnew_mod = types.ModuleType(str('{name}'))\nexec({temp_name}, new_mod.__dict__)\n".format(
                name=name, temp_name=temp_name
            )
            # update name to capture the new module object we've created
            name = "new_mod"

        elif (
            source_string[0] in " \t"
        ):  # modules won't be indented, only a class/function issue
            # source is indented to some level, so dedent it to avoid an indentation error
            source_string = textwrap.dedent(source_string)

        retrieval_string = "\nglobals()['{temp_name}'] = {name}".format(
            temp_name=temp_name, name=name
        )

        # run the exec
        self.remote_exec(source_string + retrieval_string, **kwargs)

        # retrieve from __main__ with remote_eval
        result = self.remote_eval(temp_name)

        # nuke the temp name - the remote handle will keep the module/class/function around
        self.remote_exec(
            "global {temp_name}\ndel {temp_name}".format(temp_name=temp_name)
        )

        return result

    def __del__(self):
        self.clean_up()


class HeadlessIdaRemote(HeadlessIda):
    def __init__(self, 
            host, 
            port, 
            binary_path, 
            override_import=True, 
            ftype=None, 
            processor=None):
        self.cleaned_up = False
        atexit.register(self.clean_up)
        self.conn = rpyc.connect(
            host,
            int(port),
            service=ForwardIO,  # type: ignore
            config={"sync_request_timeout": 60 * 60 * 24},
        )
        with open(binary_path, "rb") as f:
            self.conn.root.init(f.read(), ftype=ftype, processor=processor)
        if override_import:
            self.override_import()
