##
# Necessary module imports
#
import os
import os.path
import sys
import ctypes
import platform
from codecs import encode, decode

##
# PCAP libray constant value definitions.
#
PCAP_ERROR_BUF_SIZE       = 256
PCAP_FILTER_BUF_SIZE      = 2048
PCAP_OPENFLAG_PROMISCUOUS = 1
PCAP_TIMEOUT_MS           = 1
PCAP_FILTER_OPTIMIZE      = 1
PCAP_ETH_MIN_FRAME_LEN    = 60
PCAP_MODE_BLOCKING        = 0
PCAP_MODE_NON_BLOCKING    = 1

##
# Socket structure address types.
#
ADDR_TYPE_AF_UNSPEC = 0
ADDR_TYPE_AF_INET   = 2
ADDR_TYPE_AF_INET6  = 23

##
# PCAP interface structures.
#
class PCAP_IF(ctypes.Structure):
    pass

class PCAP_IF_ADDR(ctypes.Structure):
    pass

PCAP_IF._fields_ = [("next", ctypes.POINTER(PCAP_IF)),
                    ("name", ctypes.c_char_p),
                    ("description", ctypes.c_char_p),
                    ("addresses", ctypes.POINTER(PCAP_IF_ADDR)),
                    ("flags", ctypes.c_uint)]

class PCAP_IF_TIMESTAMP(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_long),
                ("tv_usec", ctypes.c_long)]

class PCAP_IF_PKT_HEADER(ctypes.Structure):
    _fields_ = [("ts", PCAP_IF_TIMESTAMP),
                ("caplen", ctypes.c_uint),
                ("len", ctypes.c_uint)]

class PCAP_IF_PKT(ctypes.Structure):
    _fields_ = [("header", PCAP_IF_PKT_HEADER),
                ("data", ctypes.POINTER(ctypes.c_ubyte))]

class PCAP_IF_BPF_INSN(ctypes.Structure):
    _fields_ = [("code", ctypes.c_ushort),
                ("jt", ctypes.c_ubyte),
                ("jf", ctypes.c_ubyte),
                ("k", ctypes.c_uint)]

class PCAP_IF_BPF_PROGRAM(ctypes.Structure):
    _fields_ = [("len", ctypes.c_uint),
                ("bf_insns", ctypes.POINTER(PCAP_IF_BPF_INSN))]

class PCAP_IF_SOCK_ADDR(ctypes.Structure):
    _fields_ = [("sa_family", ctypes.c_ushort),
                ("sa_data", ctypes.c_ubyte * 14)]

PCAP_IF_ADDR._fields_ = [("next", ctypes.POINTER(PCAP_IF_ADDR)),
                         ("addr", ctypes.POINTER(PCAP_IF_SOCK_ADDR)),
                         ("netmask", ctypes.POINTER(PCAP_IF_SOCK_ADDR)),
                         ("broadaddr", ctypes.POINTER(PCAP_IF_SOCK_ADDR)),
                         ("dstaddr", ctypes.POINTER(PCAP_IF_SOCK_ADDR))]


DISPATCH_HANDLER = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)
"""Callback function prototype used by loop(), dispatch() and flush_rx().
"""


def pcap_flush_rx_handler(user, pkt_header, pkt_data):
    """Dummy dispatch handler used by flush_rx() to consume pending rx packets.
    """
    pass


class PcapLibExceptionUnsupportedOS(Exception):
    """Exception raised by PcapLib initializer if target os name is not defined.
    """
    pass


class PcapLib():
    """Wrapper class for PCAP C library
    """

    # PCAP library error message buffer
    error_buffer = ctypes.c_char * PCAP_ERROR_BUF_SIZE

    # PCAP library capturing filter buffer
    filter_buffer = ctypes.c_char * PCAP_FILTER_BUF_SIZE


    def __init__(self):
        """PcapLib constructor

        Details
        ------- 
        - Initialize PCAP library depending on target OS.
        - Get and print PCAP library version string.
        - Get and store PCAP library device list.

        Parameters
        ----------
        target_os: Target OS on which software is used ("WINDOWS" or "LINUX")

        """

        # PCAP library handle
        self.pcaplib_handle = None
        # Flag to control padding of small ethernet packets
        self.pad_small_packets = True
        # PCAP device list
        self.p_if_list = ctypes.pointer(PCAP_IF())

        buffer = self.error_buffer()

        if (platform.system().upper() == "WINDOWS"):
            env_var_system_root = os.environ.get('SystemRoot')

            # If there is an installation of Npcap at expected location then load
            # Npcap library preceeded by a load of its corresponding "Packet.dll".
            # Otherwise try to load WinPcap library.
            if os.path.exists(env_var_system_root + "/system32/Npcap/wpcap.dll"):
                self.packetlib_handle = ctypes.CDLL(env_var_system_root + "/system32/Npcap/Packet.dll")
                self.pcaplib_handle = ctypes.CDLL(env_var_system_root + "/system32/Npcap/wpcap.dll")
            else:
                self.pcaplib_handle = ctypes.CDLL(env_var_system_root + "/system32/wpcap.dll")
        elif (platform.system().upper() == "LINUX"):
            self.pcaplib_handle = ctypes.CDLL("libpcap.so")
        else:
            raise PcapLibExceptionUnsupportedOS

        if (self.pcaplib_handle != None):
            self.__printf ("PCAP library handle: %s\n", self.pcaplib_handle)
            self.pcaplib_handle.pcap_lib_version.restype = ctypes.c_char_p
            self.__printf ("%s\n", ctypes.c_char_p(self.pcaplib_handle.pcap_lib_version()).value)
            status = self.pcaplib_handle.pcap_findalldevs(ctypes.byref(self.p_if_list), ctypes.byref(buffer))
            if (status != 0):
                self.__printf ("pcap_findalldevs() failed --> %s\n", ctypes.cast(buffer, ctypes.c_char_p).value)


    def __del__(self):
        """PcapLib destructor

        Details
        ------- 
        Free PCAP library device list
        
        """
        if (self.pcaplib_handle != None):
            if (self.p_if_list):
                self.__printf ("Release PCAP device list\n")
                self.pcaplib_handle.pcap_freealldevs.argtypes = [ctypes.c_void_p]
                self.pcaplib_handle.pcap_freealldevs(self.p_if_list)
        else:
            self.__printf ("Invalid PcapLib handle --> Do nothing\n")


    def get_device_list(self):
        """Setup a PCAP device dictionary

        Details
        ------- 
        Create a PCAP device dictionary which contains device name as key 
        and device description as its value

        Returns
        -------
        PCAP device dictionary

        """
        if_name_list = dict()

        if (self.p_if_list):
            p_if = self.p_if_list
            index = 0
            while (p_if):
                if (p_if.contents.name):
                    if (p_if.contents.description):
                        if_name_list[p_if.contents.name]=p_if.contents.description
                    else:
                        if_name_list[p_if.contents.name]="No description"
                else:
                    name = "Unknown " + str(index)
                    if_name_list[name]="No description"
                index = index+1
                p_if = p_if.contents.next
        return if_name_list


    def get_ext_device_list(self):
        """Setup extended PCAP device dictionary

        Details
        ------- 
        Create a PCAP device dictionary which contains device name as key 
        and a tuple of device description and IPv4 address string (if available) 
        as its value.

        Returns
        -------
        PCAP device dictionary

        """
        if_name_list = dict()

        if (self.p_if_list):
            p_if = self.p_if_list
            index = 0
            while (p_if):
                name = "Unknown " + str(index)
                description = "No description"
                ipv4 = ""                
                if (p_if.contents.name):
                    name = p_if.contents.name
                    if (p_if.contents.description):
                        description = p_if.contents.description

                p_addr = p_if.contents.addresses                
                while (p_addr):
                    p_if_addr = p_addr.contents.addr                    
                    if p_if_addr and p_if_addr.contents.sa_family == ADDR_TYPE_AF_INET:
                        ipv4 = "{}.{}.{}.{}".format(p_if_addr.contents.sa_data[2], 
                                                    p_if_addr.contents.sa_data[3],
                                                    p_if_addr.contents.sa_data[4],
                                                    p_if_addr.contents.sa_data[5])
                        break
                    p_addr = p_addr.contents.next

                if_name_list[name] = (description, ipv4)
                index += 1
                p_if = p_if.contents.next
        return if_name_list


    def open_live(self, if_name):
        """Open PCAP interface for live capturing by its interface name

        Parameters
        ----------
        if_name: PCAP interface name

        Returns
        -------
        PCAP interface on success, None otherwise

        """
        buffer = self.error_buffer()
        p_if = ctypes.pointer(PCAP_IF())
        self.__printf ("Open interface: %s\n", if_name)
        if (self.pcaplib_handle):
            self.pcaplib_handle.pcap_open_live.restype = ctypes.c_void_p
            self.pcaplib_handle.pcap_open_live.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_char_p]
            p_if = self.pcaplib_handle.pcap_open_live(if_name, 65536, PCAP_OPENFLAG_PROMISCUOUS, PCAP_TIMEOUT_MS, buffer)
            if (p_if):
                return p_if
            else:
                self.__printf ("pcap_open_live() failed --> %s\n", ctypes.cast(buffer, ctypes.c_char_p).value)
                return None
        else:
            return None


    def close(self, p_if):
        """Close PCAP interface

        Parameters
        ----------
        p_if: PCAP interface

        """
        if (p_if and self.pcaplib_handle):
            self.pcaplib_handle.pcap_close.argtypes = [ctypes.c_void_p]
            self.pcaplib_handle.pcap_close(p_if)


    def next_ex(self, p_if):
        """Get next packet from receive buffer

        Parameters
        ----------
        p_if: PCAP interface

        Returns
        -------
        - Received packet on success
        - Packet of length zero on timeout
        - None on error

        """
        pkt_data = ctypes.pointer(ctypes.c_ubyte())
        pkt_hdr = ctypes.pointer(PCAP_IF_PKT_HEADER())
        pkt = PCAP_IF_PKT()

        if (p_if and self.pcaplib_handle):
            self.pcaplib_handle.pcap_next_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte))]
            result = self.pcaplib_handle.pcap_next_ex(p_if, ctypes.byref(pkt_hdr), ctypes.byref(pkt_data))
            if (result > 0):
                pkt.header = pkt_hdr.contents
                pkt.data = pkt_data
                return pkt
            elif (result == 0):
                pkt.header.caplen = 0
                pkt.header.len = 0
                return pkt
            else:
                return None
        else:
            return None


    def loop(self, p_if, count, callback, user):
        """Receive number of packets in a loop using callback function

        Parameters
        ----------
        p_if: PCAP interface
        count: Number of packets to receive
        callback: Receive handler callback function
        user: User data

        Returns
        -------
        - 0:  Desired number of packets have been received
        - -1: Error occured
        - -2: Loop terminated

        """
        if (p_if and self.pcaplib_handle):
            self.pcaplib_handle.pcap_loop.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
            return self.pcaplib_handle.pcap_loop(p_if, count, DISPATCH_HANDLER(callback), user)


    def dispatch(self, p_if, count, callback, user):
        """Receive number of packets in a loop using callback function

        Parameters
        ----------
        p_if: PCAP interface
        count: Number of packets to receive
        callback: Receive handler callback function
        user: User data

        Returns
        -------
        - >=0:  Desired number of packets have been received
        - -1: Error occured
        - -2: Loop terminated

        """
        if (p_if and self.pcaplib_handle):
            self.pcaplib_handle.pcap_dispatch.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
            return self.pcaplib_handle.pcap_dispatch(p_if, count, DISPATCH_HANDLER(callback), user)


    def breakloop(self, p_if):
        """Break receive loop entered by call to dispatch() or loop()

        Parameters
        ----------
        p_if: PCAP interface

        """
        if (p_if and self.pcaplib_handle):
            self.pcaplib_handle.pcap_breakloop.argtypes = [ctypes.c_void_p]
            self.pcaplib_handle.pcap_breakloop(p_if)


    def setfilter(self, p_if, filter_string, net_mask_ipv4=0, print_filter_string=True):
        """Set capturing filter

        Parameters
        ----------
        p_if: PCAP interface
        filter_string: Text based filter description
        net_mask_ipv4: IPv4 netmask
        print_filter_string: Print set filter string flag

        Returns
        -------
        - 0: success
        - !0: error
        - None: No valid PCAP interface

        """
        buffer = self.filter_buffer()
        buffer.value = filter_string.encode('utf-8')
        filter_prog = PCAP_IF_BPF_PROGRAM()

        if (print_filter_string == True):
            self.__printf ("Set filter : %s\n", filter_string)
        if (p_if and self.pcaplib_handle):
            self.pcaplib_handle.pcap_compile.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int, ctypes.c_int]
            result = self.pcaplib_handle.pcap_compile(p_if, ctypes.byref(filter_prog), buffer, PCAP_FILTER_OPTIMIZE, net_mask_ipv4)
            if (result >= 0):
                self.pcaplib_handle.pcap_setfilter.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
                result = self.pcaplib_handle.pcap_setfilter(p_if, ctypes.byref(filter_prog))
                # Free memory allocated for filter program by pcap_compile
                self.pcaplib_handle.pcap_freecode.argtypes = [ctypes.c_void_p]
                self.pcaplib_handle.pcap_freecode(ctypes.byref(filter_prog))
            return result
        else:
            return None


    def sendpacket(self, p_if, data, flush_rx_buf = False):
        """Send a packet

        Parameters
        ----------
        p_if: PCAP interface
        data: Data to send as hex string
        flush_rx: Flush receive buffer before send

        Returns
        -------
        - 0: success
        - !0: error
        - None: No valid PCAP interface

        """
        if (p_if and self.pcaplib_handle):
            if (flush_rx_buf == True):
                self.flush_rx(p_if)
            if (self.pad_small_packets == True):
                while (len(data) < PCAP_ETH_MIN_FRAME_LEN*2):
                    data += str("0").encode('utf-8')
            buffer = decode(data, 'hex')
            self.pcaplib_handle.pcap_sendpacket.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int]
            result = self.pcaplib_handle.pcap_sendpacket(p_if, ctypes.cast(buffer, ctypes.c_char_p), len(buffer))
            return result
        else:
            return None


    def set_non_blocking(self, p_if, mode):
        """Set opened PCAP interface to blocking or non blocking mode

        Parameters
        ----------
        p_if: PCAP interface
        mode: Set blocking mode to PCAP_MODE_BLOCKING or PCAP_MODE_NON_BLOCKING

        Returns
        -------
        - 0: success
        - !0: error
        - None: No valid PCAP interface

        """
        buffer = self.error_buffer()
        if (p_if and self.pcaplib_handle):
            self.pcaplib_handle.pcap_setnonblock.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_char_p]
            result = self.pcaplib_handle.pcap_setnonblock(p_if, mode, buffer)
            if (result < 0):
                self.__printf ("set_non_blocking() failed --> %s\n", ctypes.cast(buffer, ctypes.c_char_p).value)
            return result
        else:
            return None


    def enable_small_packet_padding(self, enable):
        """Enable/Disable padding of short packets

        Parameters
        ----------
        enable: True = enable, False = disable

        """
        self.pad_small_packets = enable


    def dump_pkt(self, pkt):
        """Dump PCAP packet

        Parameters
        ----------
        pkt: PCAP packet which consists of header structure and data

        """
        self.__printf ("Timestamp: %d %d\n", pkt.header.ts.tv_sec, pkt.header.ts.tv_usec)
        self.__printf ("Length:    %d (%d)\n", pkt.header.caplen, pkt.header.len)
        data_buf = ""
        for i in range(0, pkt.header.caplen):
            data_buf += ''.join('%02x'%pkt.data[i])
        data_line = "0000 | "
        self.__printf ("------------------------------------------------------\n")
        for idx in range(0,len(data_buf),2):
            if ((idx > 0) and (((idx) % 32) == 0)):
                self.__printf ("%s\n", data_line)
                data_line = format((int(idx/2)), '04x') + " | "
            data_line += data_buf[idx] + data_buf[idx+1] + " "
        if (len(data_line) > 0):
            self.__printf ("%s\n", data_line)
        self.__printf ("------------------------------------------------------\n")


    def flush_rx(self, p_if):
        """Flush pending packets from receive buffer

        Parameters
        ----------
        p_if: PCAP interface

        Returns
        -------
        - 0: Flush sucessfully done
        - !0: Error
        - None: Packet processing loop terminated
        """
        if (p_if and self.pcaplib_handle):
            self.pcaplib_handle.pcap_dispatch.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
            # Call PCAP dispatch until all packets have been consumed or
            # return value signals an exceptional condition.
            while True:
                ret_val = self.pcaplib_handle.pcap_dispatch(p_if, -1, DISPATCH_HANDLER(pcap_flush_rx_handler), 0)
                if ret_val <= 0:
                    break
            return ret_val


    def __printf(self, format, *args):
        """Simple stdout print function

        Details
        -------
        Formatted printf like function usable by Python 2.7.x and 3.x code.

        Parameters
        ----------
        format: Format string
        args: Optional argument list

        """
        self.pcaplib_handle.pcap_dispatch.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
        # Call PCAP dispatch until all packets have been consumed or
        # return value signals an exceptional condition.
        sys.stdout.write(format % args)
