import platform
import os
import socket
from enum import Enum
from threading import Lock

SYSNAME = platform.system()
WIN_NAME = "Windows"
OSX_NAME = "Darwin"
LINUX_NAME = "Linux"


class IPCResult(Enum):
    """
    IPC result codes.\n
    A list of possible result codes the IPC can send back.\n
    Each one of them is what we call an "opcode" or "tag" and is the
    first byte sent by the IPC to differentiate between results.
    """
    IPC_OK = 0
    """IPC command successfully completed"""
    IPC_FAIL = 0xFF
    """IPC command failed to complete"""


class IPCCommand(Enum):
    """
        IPC Command messages opcodes. \n
        A list of possible operations possible by the IPC. \n
        Each one of them is what we call an "opcode" and is the first
        byte sent by the IPC to differentiate between commands.
    """

    MsgRead8 = 0
    """Read 8 bit value to memory."""
    MsgRead16 = 1
    """Read 16 bit value to memory."""
    MsgRead32 = 2
    """Read 32 bit value to memory."""
    MsgRead64 = 3
    """Read 64 bit value to memory."""
    MsgWrite8 = 4
    """Write 8 bit value to memory."""
    MsgWrite16 = 5
    """Write 16 bit value to memory."""
    MsgWrite32 = 6
    """Write 32 bit value to memory."""
    MsgWrite64 = 7
    """Write 64 bit value to memory."""
    MsgVersion = 8
    """Returns the emulator version."""
    MsgSaveState = 9
    """Saves a savestate."""
    MsgLoadState = 0xA
    """Loads a savestate."""
    MsgTitle = 0xB
    """Returns the game title."""
    MsgID = 0xC
    """Returns the game ID."""
    MsgUUID = 0xD
    """Returns the game UUID."""
    MsgGameVersion = 0xE
    """Returns the game verion."""
    MsgStatus = 0xF
    """Returns the emulator status."""
    MsgUnimplemented = 0xFF
    """Unimplemented IPC message."""


class IPCStatus(Enum):
    """
    Result code of the IPC operation. \n
    A list of result codes that should be returned, or thrown, depending
    on the state of the result of an IPC command.
    """

    Success = 0
    """IPC command successfully completed."""
    Fail = 1
    """IPC command failed to execute."""
    OutOfMemory = 2
    """IPC command too big to send."""
    NoConnection = 3
    """Cannot connect to the IPC socket."""
    Unimplemented = 4
    """Unimplemented IPC command."""
    Unknown = 5
    """Unknown status."""


class IPCBuffer:
    size: int
    buffer: bytearray | memoryview

    def __init__(self, size: int, buffer: bytearray | memoryview):
        self.size = size
        self.buffer = buffer


class BatchCommand:
    ipc_message: IPCBuffer
    ipc_return: IPCBuffer
    return_locations: list[int]
    msg_size: int
    reloc: bool

    def __init__(self, ipc_message: IPCBuffer, ipc_return: IPCBuffer,
                 return_locations: list[int], msg_size: int, reloc: bool):
        self.ipc_message = ipc_message
        self.ipc_return = ipc_return
        self.return_locations = return_locations
        self.msg_size = msg_size
        self.reloc = reloc

    def __del__(self):
        del self.ipc_message.buffer
        del self.ipc_return.buffer


class EmuStatus(Enum):
    """
    Emulator status enum.\n
    A list of possible emulator statuses.
    """
    Running = 0
    """Game is running."""
    Paused = 1
    """Game is paused."""
    Shutdown = 2
    """Game is shutdown."""


class PINEServerNotSetupError(Exception):
    def __init__(self, slot: int):
        msg = f'Emulator is not running or has not set up their PINE server (Slot {slot}).'
        super().__init__(msg)


class IPCError(Exception):
    status: IPCStatus

    def __init__(self, status: IPCStatus | IPCResult | IPCCommand):
        self.status = status
        msg = ""

        if isinstance(status, IPCCommand):
            match status:
                case 0xFF:
                    msg = "Unimplemented IPC message."
        elif isinstance(status, IPCResult):
            match status:
                case 0:
                    msg = "IPC command successfully completed."
                case 0xFF:
                    msg = "IPC command failed to complete."
                case _:
                    msg = "Unknown"
        else:
            match status:
                case 0:
                    msg = "IPC command successfully completed."
                case 1:
                    msg = "IPC command failed to execute."
                case 2:
                    msg = "IPC command too big to send."
                case 3:
                    msg = "Cannot connect to the IPC socket."
                case 4:
                    msg = "Unimplemented IPC command."
                case _:
                    msg = "Unknown status."

        super().__init__(msg)


def from_le(buf: bytes | bytearray) -> int:
    """
    Transforms an array of Little-Endian bytes into an int
    :param buf: buffer containing all the bytes needed
    :return: integer
    """
    return int.from_bytes(buf, "little")


def to_le(i: int, length: int = 4) -> bytes:
    """
    Transforms an integer to a Little-Endian array of bytes
    :param i: The integer to be transformed
    :param length: How many bytes is the integer (Power of 2 preferably. e.g. 1, 2, 4, 8)
    :return: The array of bytes
    """
    return int.to_bytes(i, length, "little")


class Shared:
    slot: int
    sock: socket.socket
    sock_state: bool = False
    SOCKET_NAME: str

    MAX_IPC_SIZE = 650000
    MAX_IPC_RETURN_SIZE = 450000
    MAX_BATCH_REPLY_COUNT = 500000

    ret_buffer: bytearray
    mv_ret_buffer: memoryview
    ipc_buffer: bytearray
    mv_ipc_buffer: memoryview
    batch_len: int = 0
    reply_len: int = 0
    needs_reloc: bool = False
    arg_cnt: int = 0
    batch_arg_place: list[int]
    batch_blocking: Lock
    ipc_blocking: Lock
    cmd_lock: Lock

    def init_socket(self):
        if SYSNAME == WIN_NAME:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
            conn_address = "127.0.0.1"
        else:
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, 0)
            conn_address = self.SOCKET_NAME

        try:
            self.sock.connect(conn_address)
        except FileNotFoundError:
            self.sock.close()
            self.sock_state = False
            raise PINEServerNotSetupError(self.slot)

        self.sock_state = True

    def batch_safety_checks(self, command_size: int, reply_size: int = 0) -> bool:
        return \
            (self.batch_len + command_size >= self.MAX_IPC_SIZE) or \
            (self.reply_len + reply_size >= self.MAX_IPC_RETURN_SIZE) or \
            (self.arg_cnt + 1 >= self.MAX_BATCH_REPLY_COUNT)

    def _emu_state(self, command: IPCCommand, slot: int, batch: bool = False) -> None | memoryview:
        """
        Internal function for savestate IPC messages. \n
        On error throws an IPCStatus.
        :parameter command: The command to use.
        :parameter slot: The savestate slot to use.
        :parameter batch: Flag to enable batch processing.
        :returns: The IPC Message if in batch mode, otherwise nothing.
        :raises IPCError: Containing an IPCStatus
        """
        if batch:
            if self.batch_safety_checks(2):
                raise IPCError(IPCStatus.OutOfMemory)

            mv = memoryview(self.ipc_buffer)
            mv = mv[self.batch_len:]
            mv[0] = command.value
            mv[1] = slot
            self.batch_len += 2
            self.arg_cnt += 1
            return mv
        else:
            with self.cmd_lock:
                self.ipc_buffer[0:4] = to_le(4 + 2)
                self.ipc_buffer[4] = command.value
                self.ipc_buffer[5] = slot
                self.send_command(IPCBuffer(4 + 1 + 1, self.ipc_buffer),
                                  IPCBuffer(4 + 1, self.ret_buffer))
                return

    def _string_commands(self, ipc_cmd: IPCCommand, batch: bool = False) -> str | memoryview:
        """
        Internal function for IPC messages returning strings. \n
        On error throws an IPCStatus.
         * Format: XX
         * Legend: XX = IPC Tag.
         * Return: ZZ * 256
         * Legend: ZZ = text.
        :param ipc_cmd: IPCCommand to use
        :param batch: True if in batch mode.
        :return: IPC Message if in batch mode, else nothing.
        :exception IPCStatus:
        """
        if batch:
            if self.batch_safety_checks(1, 4):
                raise IPCError(IPCStatus.OutOfMemory)

            cmd = memoryview(self.ipc_buffer)
            cmd = cmd[self.batch_len:]
            cmd[0] = ipc_cmd.value
            self.batch_len += 1
            #  MSB is used as a flag to warn pine that the reply is a VLE!
            self.batch_arg_place[self.arg_cnt] = (self.reply_len | 0x8000000)
            self.reply_len += 4
            self.needs_reloc = True
            self.arg_cnt += 1
            return cmd
        else:
            with self.cmd_lock:
                self.ipc_buffer[0:4] = to_le(4 + 1)
                self.ipc_buffer[4] = ipc_cmd.value
                self.send_command(IPCBuffer(4 + 1, self.mv_ipc_buffer),
                                  IPCBuffer(self.MAX_IPC_RETURN_SIZE, self.mv_ret_buffer))
                return self.get_reply(ipc_cmd, self.ret_buffer, 5)

    def _format_beginning(self, buf: bytearray | memoryview,
                          address: int, command: IPCCommand,
                          size: int = 0, batch: bool = False) -> bytearray | memoryview:
        """
        Formats an IPC buffer. \n
        Creates a new buffer with IPC opcode set and first address argument
        currently used for memory IPC commands.

        :param buf: Bytearray or memoryview to the buffer.
        :param address: 32-bit (4 byte) Memory address.
        :param command: The IPC message tag/opcode.
        :param size: Size of the buffer to allocate (Non-batch only)
        :param batch: If it's formatting for a batch of commands.

        :return: The IPC buffer.
        """
        if batch:
            buf[0] = command.value
            buf[1:5] = to_le(address, 4)
            return memoryview(buf)[5:]
        else:
            buf[0:4] = to_le(size, 4)
            buf[4] = command.value
            buf[5:9] = to_le(address, 4)
            return buf

    def get_reply(self, cmd: IPCCommand, ret: bytearray | BatchCommand, place: int):
        if isinstance(ret, BatchCommand):
            buf = ret.ipc_return.buffer
            loc = ret.return_locations[place]
        else:
            buf = ret
            loc = place

        match cmd:
            case IPCCommand.MsgRead8:
                return buf[loc]
            case IPCCommand.MsgRead16:
                return from_le(buf[loc:loc+2])
            case IPCCommand.MsgRead32:
                return from_le(buf[loc:loc+4])
            case IPCCommand.MsgRead64:
                return from_le(buf[loc:loc+8])
            case IPCCommand.MsgStatus:
                return EmuStatus(value=buf[loc])
            case (IPCCommand.MsgVersion | IPCCommand.MsgID |
                  IPCCommand.MsgTitle | IPCCommand.MsgUUID |
                  IPCCommand.MsgGameVersion):
                size = from_le(buf[loc:loc+4])
                return buf[loc + 4:loc + 4 + size].copy().decode().strip('\0')
            case _:
                raise IPCError(IPCStatus.Unimplemented)

    def send_command(self, cmd: IPCBuffer | BatchCommand, rt: IPCBuffer = None):
        if isinstance(cmd, BatchCommand):
            command = cmd.ipc_message
            ret = cmd.ipc_return
        else:
            command = cmd
            ret = rt

        if not self.sock_state:
            self.init_socket()

        total_sent = 0

        while total_sent < command.size:
            bytes_sent = self.sock.send(command.buffer[total_sent:command.size])

            if bytes_sent < 0:
                self.sock.close()
                self.sock_state = False
                raise IPCError(IPCStatus.NoConnection)

            total_sent += bytes_sent

        #  print("packet sent:")
        #  hexdump(command.buffer, command.size)

        receive_length = 0
        end_length = 4

        while receive_length < end_length:
            tmp_length = self.sock.recv_into(ret.buffer, ret.size - receive_length)

            if tmp_length <= 0:
                receive_length = 0
                break

            receive_length += tmp_length

            if (end_length == 4) and (receive_length >= 4):
                end_length = from_le(ret.buffer[0:5])
                if end_length > self.MAX_IPC_SIZE:
                    receive_length = 0
                    break

        #  print("reply received:")
        #  hexdump(ret.buffer, receive_length)

        if (receive_length == 0) or (ret.buffer[4] == IPCResult.IPC_FAIL):
            raise IPCError(IPCResult.IPC_FAIL)

        if isinstance(cmd, BatchCommand):
            if cmd.reloc:
                reloc_add = 0
                for i in range(cmd.msg_size):
                    cmd.return_locations[i] += reloc_add
                    if (cmd.return_locations[i] & 0x80000000) != 0:
                        rl = cmd.return_locations[i]
                        cmd.return_locations[i] = (rl & ~0x80000000)
                        reloc_add += from_le(ret.buffer[rl:rl+5])

    def initialize_batch(self):
        self.batch_blocking.acquire()
        self.ipc_blocking.acquire()
        self.batch_len = 4
        self.reply_len = 5
        self.needs_reloc = False
        self.arg_cnt = 0

    def finalize_batch(self) -> BatchCommand:
        self.ipc_buffer[0:4] = to_le(self.batch_len)

        bl = self.batch_len
        rl = self.MAX_IPC_SIZE if self.needs_reloc else self.reply_len
        c_cmd = self.ipc_buffer[:self.batch_len]
        c_ret = self.ret_buffer[:rl]
        arg_place = self.batch_arg_place[:self.arg_cnt]

        self.batch_blocking.release()
        self.ipc_blocking.release()

        return BatchCommand(
            IPCBuffer(bl, c_cmd),
            IPCBuffer(rl, c_ret),
            arg_place, self.arg_cnt, self.needs_reloc
        )

    def read(self, address: int, var_size: int, batch: bool = False):
        match var_size:
            case 1:
                tag = IPCCommand.MsgRead8
            case 2:
                tag = IPCCommand.MsgRead16
            case 4:
                tag = IPCCommand.MsgRead32
            case 8:
                tag = IPCCommand.MsgRead64
            case _:
                raise IPCError(IPCCommand.MsgUnimplemented)

        if batch:
            if self.batch_safety_checks(5, var_size):
                raise IPCError(IPCStatus.OutOfMemory)

            mv = memoryview(self.ipc_buffer)
            mv = mv[self.batch_len:]
            cmd = self._format_beginning(mv, address, tag, 0, True)
            self.batch_len += 5
            self.batch_arg_place[self.arg_cnt] = self.reply_len
            self.reply_len += var_size
            self.arg_cnt += 1
            return cmd
        else:
            with self.cmd_lock:
                cmd = IPCBuffer(4 + 5, self._format_beginning(self.ipc_buffer, address, tag, 4 + 5))
                ret = IPCBuffer(1 + var_size + 4, self.ret_buffer)
                self.send_command(cmd, ret)
                return self.get_reply(tag, self.ret_buffer, 5)

    def write(self, address: int, value: int, nbytes: int, batch: bool = False):
        match nbytes:
            case 1:
                tag = IPCCommand.MsgWrite8
            case 2:
                tag = IPCCommand.MsgWrite16
            case 4:
                tag = IPCCommand.MsgWrite32
            case 8:
                tag = IPCCommand.MsgWrite64
            case _:
                raise IPCError(IPCCommand.MsgUnimplemented)

        if batch:
            mv = memoryview(self.ipc_buffer)
            mv = mv[self.batch_len:]
            cmd = self._format_beginning(mv, address, tag, 0, True)
            cmd[0:nbytes] = to_le(value, nbytes)
            self.batch_len += 5 + nbytes
            self.arg_cnt += 1
            return cmd
        else:
            with self.cmd_lock:
                size = 4 + 5 + nbytes
                cmd = self._format_beginning(self.ipc_buffer, address, tag, size)
                cmd[9:9 + nbytes] = to_le(value, nbytes)
                self.send_command(IPCBuffer(size, cmd), IPCBuffer(1 + 4, self.ret_buffer))
                return

    def version(self, batch: bool = False):
        return self._string_commands(IPCCommand.MsgVersion, batch)

    def status(self, batch: bool = False):
        tag = IPCCommand.MsgStatus

        if batch:
            if self.batch_safety_checks(1, 4):
                raise IPCError(IPCStatus.OutOfMemory)

            mv = memoryview(self.ipc_buffer)
            mv = mv[self.batch_len:]
            mv[0] = tag.value
            self.batch_len += 1
            self.batch_arg_place[self.arg_cnt] = self.reply_len
            self.reply_len += 4
            self.arg_cnt += 1
            return mv
        else:
            with self.cmd_lock:
                self.ipc_buffer[0:4] = to_le(4 + 1)
                self.ipc_buffer[4] = tag.value
                self.send_command(IPCBuffer(4 + 1, self.mv_ipc_buffer),
                                  IPCBuffer(4 + 1 + 4, self.mv_ret_buffer))
                return self.get_reply(tag, self.ret_buffer, 5)

    def get_game_title(self, batch: bool = False) -> str | bytearray:
        """
            Retrieves the game title. \n
            * Format: XX \n
            * Legend: XX = IPC Tag. \n
            * Return: YY YY YY YY (ZZ*??) \n
            * Legend: YY = string size, ZZ = title string.
            :parameter batch: Flag to enable batch processing or not. \n
            :return: IPCMessage, str: If in batch mode the IPC message otherwise the Game Title string. \n
            :exception IPCError: containing IPCStatus
        """

        return self._string_commands(IPCCommand.MsgTitle, batch)

    def get_game_id(self, batch: bool = False) -> str | bytearray:
        """
        Retrieves the game ID.\n
        * Format: XX \n
        * Legend: XX = IPC Tag.\n
        * Return: YY YY YY YY (ZZ*??)\n
        * Legend: YY = string size, ZZ = ID string.
        :parameter batch: Flag to enable batch processing or not.
        :return: If in batch mode the IPC message otherwise the ID string.
        :exception IPCError: Containing IPCStatus
        """

        return self._string_commands(IPCCommand.MsgID, batch)

    def get_game_uuid(self, batch: bool = False) -> str | bytearray:
        """
        Retrieves the game UUID.\n
        * Format: XX \n
        * Legend: XX = IPC Tag.\n
        * Return: YY YY YY YY (ZZ*??)\n
        * Legend: YY = string size, ZZ = ID string.
        :parameter batch: Flag to enable batch processing or not.
        :return: If in batch mode the IPC message otherwise the UUID string.
        :exception IPCError: Containing IPCStatus
        """

        return self._string_commands(IPCCommand.MsgUUID, batch)

    def get_game_version(self, batch: bool = False) -> str | bytearray:
        """
        Retrieves the game ID.\n
        * Format: XX \n
        * Legend: XX = IPC Tag.\n
        * Return: YY YY YY YY (ZZ*??)\n
        * Legend: YY = string size, ZZ = ID string.
        :parameter batch: Flag to enable batch processing or not.
        :return: If in batch mode the IPC message otherwise the version string.
        :exception IPCError: Containing IPCStatus
        """

        return self._string_commands(IPCCommand.MsgGameVersion, batch)

    def save_state(self, slot: int, batch: bool = False) -> None | bytearray:
        """
        Asks the emulator to save a savestate.\n
        * Format: XX YY \n
        * Legend: XX = IPC Tag, YY = Slot.

        :parameter slot: A byte-size int informing the savestate slot to use.
        :parameter batch: Flag to enable batch processing or not.

        :return: IPCMessage | None: If in batch mode the IPC message otherwise None.

        :exception IPCError: Containing IPCStatus
        """

        return self._emu_state(IPCCommand.MsgSaveState, slot, batch)

    def load_state(self, slot: int, batch: bool = False) -> None | bytearray:
        """
        Asks the emulator to load a savestate.\n
        * Format: XX YY \n
        * Legend: XX = IPC Tag, YY = Slot.

        :parameter slot: A byte-size int informing the savestate slot to use.
        :parameter batch: Flag to enable batch processing or not.

        :return: IPCMessage | None: If in batch mode the IPC message otherwise None.

        :exception IPCError: Containing IPCStatus
        """

        return self._emu_state(IPCCommand.MsgLoadState, slot, batch)

    def __init__(self, slot: int, emulator_name: str, default_slot: bool):
        if slot > 65536:
            raise IPCError(IPCStatus.NoConnection)

        self.slot = slot

        if SYSNAME == OSX_NAME:  # OSX
            runtime_dir = os.getenv("TMPDIR")
        else:
            runtime_dir = os.getenv("XDG_RUNTIME_DIR")

        #  fallback in case OSX or other OSes don't implement the XDG base spec
        if runtime_dir == '':
            self.SOCKET_NAME = f"/tmp/{emulator_name}.sock"
        else:
            self.SOCKET_NAME = f'{runtime_dir}/{emulator_name}.sock'

        if not default_slot:
            self.SOCKET_NAME += f".{slot}"

        self.batch_blocking = Lock()
        self.ipc_blocking = Lock()
        self.cmd_lock = Lock()

        self.ret_buffer = bytearray(self.MAX_IPC_RETURN_SIZE)
        self.mv_ret_buffer = memoryview(self.ret_buffer)
        self.ipc_buffer = bytearray(self.MAX_IPC_SIZE)
        self.mv_ipc_buffer = memoryview(self.ipc_buffer)
        self.batch_arg_place = list[int]([0 for _ in range(self.MAX_BATCH_REPLY_COUNT)])
        self.init_socket()

    def __del__(self):
        self.sock.close()

        del self.ret_buffer
        del self.ipc_buffer
        del self.batch_arg_place


class PCSX2(Shared):
    def __init__(self, slot: int = 0):
        """
        PCSX2 session Initializer with a specified slot.
        :param slot: Slot to use for this IPC session.
        """
        super().__init__(28011 if (slot == 0) else slot, 'pcsx2', slot == 0)


class RPCS3(Shared):
    def __init__(self, slot: int = 0):
        """
        RPCS3 session Initializer with a specified slot.
        :param slot: Slot to use for this IPC session.
        """
        super().__init__(28012 if (slot == 0) else slot, 'rpcs3', slot == 0)
