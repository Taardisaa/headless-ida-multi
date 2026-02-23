import argparse
import code

from rpyc.utils.server import ThreadedServer
from . import HeadlessIda, HeadlessIdaRemote, HeadlessIdaServer


def headlessida_cli():
    """
    Command-line interface for HeadlessIDA.
    
    Parses command-line arguments to initialize a HeadlessIDA instance (local or remote)
    and execute optional scripts or commands against a binary file.
    
    Arguments:
        idat_path (str): Path to IDA Pro TUI executable or Host:Port of remote HeadlessIDA server
        binary_path (str): Path to the binary file to analyze
        script_path (str, optional): Path to a Python script to execute
        -f, --ftype (str, optional): File type prefix for interpreting the input file
        -p, --processor (str, optional): Processor type (e.g., arm:ARMv6, mips:R3000)
        -c, --command (str, optional): Python command to execute after script
    
    Returns:
        None
    
    Behavior:
        - If idat_path contains ":", initializes a remote HeadlessIDA connection
        - Otherwise, initializes a local HeadlessIDA instance
        - Executes script_path if provided
        - Executes command if provided via -c flag
        - If neither script nor command is provided, launches interactive interpreter
    """
    parser = argparse.ArgumentParser(description='Headless IDA')
    parser.add_argument(
        'idat_path', help='Path to IDA Pro TUI executable / Host:Port of remote HeadlessIDA server')
    parser.add_argument('binary_path', help='Path to binary to analyze')
    parser.add_argument('script_path', nargs='?', help='Path to script to run')
    parser.add_argument('-f', '--ftype', nargs='?',
                        help='interpret the input file as the specified file type The file type is specified as a '
                             'prefix of a file type visible in the "load file" dialog box')
    parser.add_argument('-p', '--processor', nargs='?',
                        help='specify processor type (e.g., arm:ARMv6, arm:ARMv7-A, mips:R3000, etc.)')
    parser.add_argument('-c', '--command', help='Command to run after script')

    args = parser.parse_args()

    if ":" in args.idat_path:
        host, port = args.idat_path.split(":")
        headlessida = HeadlessIdaRemote(host, int(port), args.binary_path, ftype=args.ftype, processor=args.processor)
    else:
        headlessida = HeadlessIda(args.idat_path, args.binary_path, ftype=args.ftype, processor=args.processor)
    headlessida_dict = {"headlessida": headlessida, "HeadlessIda": HeadlessIda}

    if args.script_path:
        with open(args.script_path) as f:
            exec(compile(f.read(), args.script_path, 'exec'), headlessida_dict)
    elif args.command:
        exec(compile(args.command, '<string>', 'single'), headlessida_dict)

    else:
        code.interact(local=locals())


def headlessida_server_cli():
    """
    CLI entry point for starting the Headless IDA Server.

    Parses command-line arguments for IDA Pro TUI executable path, host, and port,
    then initializes and starts a threaded RPC server that exposes HeadlessIdaServer
    functionality with all attributes allowed.

    Command-line Arguments:
        idat_path (str): Path to IDA Pro TUI executable.
        host (str): Host address to bind the server to.
        port (int): Port number to listen on.

    Raises:
        SystemExit: If required arguments are missing or port is not a valid integer.
    """
    parser = argparse.ArgumentParser(description='Headless IDA Server')
    parser.add_argument('idat_path', help='Path to IDA Pro TUI executable')
    parser.add_argument('host', help='Host to bind to')
    parser.add_argument('port', type=int, help='Port to listen on')

    args = parser.parse_args()

    ThreadedServer(HeadlessIdaServer(args.idat_path), hostname=args.host, port=args.port,
                   protocol_config={"allow_all_attrs": True}).start()