"""Variant 1."""
from abc import ABC, abstractmethod
import fcntl
import struct
import socket
from typing import Any, Type


# Interface flags
IFF_BROADCAST = 0x0002
IFF_UP = 0x0001
IFF_LOOPBACK = 0x0008
IFF_POINTOPOINT = 0x0010
IFF_NOARP = 0x0040
IFF_AUTOUP = 0x0080
IFF_PROMISC = 0x0100
IFF_ALLMULTI = 0x0200
IFF_SIMPLEX = 0x0800
IFF_LINK = 0x1000
IFF_AUTO_CONFIGURED = 0x2000
IFF_CONFIGURING = 0x4000
IFF_MULTICAST = 0x8000
IFF_VIRTUAL = 0x2000000000
IFF_DYNAMIC = 0x8000

# ioctl commands
SIOCGIFCONF = 0x8912
SIOCGIFFLAGS = 0x8913
SIOCGIFNETMASK = 0x891b
SIOCSIFNETMASK = 0x891C
SIOCGIFADDR = 0x8915
SIOCSIFADDR = 0x8916
SIOCGIFHWADDR = 0x8927
SIOCADDRT = 0x890B
SIOCDELRT = 0x890C
RTF_UP = 0x0001
RTF_GATEWAY = 0x0002


class Command(ABC):
    """Abstract class for command pattern."""

    @abstractmethod
    def execute(self):
        """
        Contain all logic.

        The only one public method.
        """
        pass


class GetIntFieldValueCommand(Command):
    """Abstract class for generating report field value classes."""

    @abstractmethod
    def __init__(self, ifname: str) -> None:
        """Initiate variables.

        Args:
            ifname (str): Network interface name.
        """

    @abstractmethod
    def execute(self) -> str:
        """Run command.

        Returns:
            str: report_value
        """


class GetInterfaceParamViaIoctl(Command):
    """Get interface param via ioctl."""

    def __init__(self, ifname: str, flag: int) -> None:
        """Init variables."""
        self.ifname = ifname
        self.flag = flag

        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.arg = struct.pack('256s', bytes(self.ifname, 'utf-8'))
        super().__init__()

    def execute(self) -> bytes:
        """Run command.

        Returns:
            bytes: raw ioctl output
        """
        output_hex: bytes = fcntl.ioctl(self.s.fileno(), self.flag, self.arg)
        return output_hex


class CheckInterfaceFlagCommand(Command):
    """Check flag is set on a interface."""

    def __init__(self, flags_raw: bytes, checked_flag: int) -> None:
        """Init variables."""
        self.flags = flags_raw
        self.checked_flag = checked_flag

    def execute(self) -> bool:
        """Run command."""
        flags_int, = struct.unpack('H', self.flags)
        return bool(flags_int & self.checked_flag)


class GetInterfaceStatusCommand(GetIntFieldValueCommand):
    """Get intreface status."""

    flag = SIOCGIFFLAGS
    ioctl_command = GetInterfaceParamViaIoctl
    flag_checker_command = CheckInterfaceFlagCommand

    def __init__(self, ifname: str) -> None:
        """Init variables."""
        self.ifname = ifname

    def execute(self) -> str:
        """Run command."""
        flags_hex = self.ioctl_command(self.ifname, self.flag).execute()[16:18]
        is_flag_set = self.flag_checker_command(flags_hex, IFF_UP).execute()
        return 'up' if is_flag_set else 'down'


class GetInterfaceIpAddressCommand(GetIntFieldValueCommand):
    """Get interface ip address."""

    flag = SIOCGIFADDR
    ioctl_command = GetInterfaceParamViaIoctl

    def __init__(self, ifname: str) -> None:
        """Init variables."""
        self.ifname = ifname

    def execute(self) -> str:
        """Run command."""
        ip_raw: bytes = self.ioctl_command(self.ifname, self.flag).execute()[20:24]
        return socket.inet_ntoa(ip_raw)


class GetInterfacPrefixCommand(GetIntFieldValueCommand):
    """Get interface network prefix."""

    flag = SIOCGIFNETMASK
    ioctl_command = GetInterfaceParamViaIoctl

    def __init__(self, ifname: str) -> None:
        """Init variables."""
        self.ifname = ifname

    def execute(self) -> str:
        """Run command."""
        mask_hex = self.ioctl_command(self.ifname, self.flag).execute()[20:24]
        return socket.inet_ntoa(mask_hex)


class GetInterfaceMacAddressCommand(GetIntFieldValueCommand):
    """Get mac-address in xx.xx.xx.xx.xx.xx format."""

    flag = SIOCGIFHWADDR
    ioctl_command = GetInterfaceParamViaIoctl

    def __init__(self, ifname: str) -> None:
        """Init variables."""
        self.ifname = ifname

    def execute(self) -> str:
        """Run command."""
        maс_hex = self.ioctl_command(self.ifname, self.flag).execute()[18:24]
        mac = '.'.join(['%02x' % char for char in bytearray(maс_hex)])
        return mac


class GetInterfaceNameCommand(GetIntFieldValueCommand):
    """Get interface name."""

    def __init__(self, ifname: str) -> None:
        """Init variables."""
        self.ifname = ifname

    def execute(self) -> str:
        """Run command."""
        return self.ifname


INTERFACE_REPORT_FIELDS_FABRIC: dict[str, Type[GetIntFieldValueCommand]] = {
    'name': GetInterfaceNameCommand,
    'status': GetInterfaceStatusCommand,
    'ip': GetInterfaceIpAddressCommand,
    'netmask': GetInterfacPrefixCommand,
    'mac': GetInterfaceMacAddressCommand,
}


class MakeInterfaceSummaryReportCommand(Command):
    """Make interface summary report."""

    def __init__(
        self, ifname: str, report_fields: list[str], field_fabric: dict[str, Type[GetIntFieldValueCommand]],
    ) -> None:
        """Init variables."""
        self.ifname = ifname
        self.report_fields = report_fields
        self.field_fabric = field_fabric

        self.report: dict[str, Any] = {}

    def execute(self) -> dict[str, Any]:
        """Run command."""
        for field in self.report_fields:
            self.report[field] = self.field_fabric[field](self.ifname).execute()
        return self.report
