#
# Necessary module imports
#
import sys
# Add parent directory to OS depending path to find pypcaplib
sys.path += [".."]
import threading
from datetime import datetime
from datetime import timedelta
from pypcaplib import *
from optparse import OptionParser

# Map input() to raw_input() for Python 2.7.x
try:
    input = raw_input
except NameError:
    pass

##
# @brief        TimeoutError
#
# @details      Raised by receive_pkt() if there is no response
#
class TimeoutError(Exception):
    pass

##
# @brief        ReceiveError
#
# @details      Raised by receive_pkt() in case of PCAP receive error
#
class ReceiveError(Exception):
    pass

##
# @brief        Receive Thread
#

class ReceiveThread(threading.Thread):
    def __init__(self, pcap_if):
        threading.Thread.__init__(self)
        self.pcap_if = pcap_if

    def run(self):
        printf("Start Receive Thread\n")
        pcaplib.dispatch(self.pcap_if, 1, dispatch_handler, 0)

##
# @brief        Simple stdout print function
#
# @details      Formatted printf like function usable by
#               Python 2.7.x and 3.x code.
#
# @param [in]   format    Format string
# @param [in]   arfs      Optional argument list
#
def printf(format, *args):
    sys.stdout.write(format % args)

##
# @brief        Print list of available PCAP interfaces
#
# @param [in]   if_dict    Dictionary of interface id's and names
#
def print_pcap_interface_list(if_dict):
    keys = if_dict.keys()
    if_idx = 0
    for key in keys:
        printf ("%d : %s --> %s\n", if_idx, key, if_dict[key])
        if_idx += 1

##
# @brief        Get current date/time as milliseconds
#
# @return       Current date/time , unit milliseconds
#
def get_datetime_ms():
    dt = datetime.now()
    return ((dt.day * 24 * 60 * 60 + dt.second) * 1000 + dt.microsecond / 1000.0)

##
# @brief        Receive packet
#
# @param [in]   timeout        Receive timeout, unit: ms
# @param [in]   dump_packet    Flag to control enable/disable packet dump
#
# @return    RMU response object if packet has been received, None otherwise
#
def receive_pkt (pcap_if, timeout = 1000, dump_packet = False):
    timeout_ms = get_datetime_ms() + timeout
    pkt = PCAP_IF_PKT()
    while (True):
        pkt = pcaplib.next_ex(pcap_if)
        if (pkt == None):
            raise ReceiveError
        elif (pkt.header.caplen > 0):
            if (dump_packet == True):
                printf("\n")
                pcaplib.dump_pkt(pkt)
                printf("\n")
            data_buf = ""
            for i in range(0, pkt.header.caplen):
                data_buf += ''.join('%02x'%pkt.data[i])
            return data_buf
        elif (pkt.header.caplen == 0) and (get_datetime_ms() > timeout_ms):
            raise TimeoutError

##
# @brief        Receive handler registered during calls of dispatch() or loop()
#
# @param [in]   user         User data
# @param [in]   pkt_header   PCAP packet header structure
# @param [in]   pkt_data     PCAP packet data
#
def dispatch_handler(user, pkt_header, pkt_data):
    pkt        = PCAP_IF_PKT()
    header     = ctypes.cast(pkt_header, ctypes.POINTER(PCAP_IF_PKT_HEADER))
    pkt.header = header.contents
    pkt.data   = ctypes.cast(pkt_data, ctypes.POINTER(ctypes.c_ubyte))
    printf("\n")
    pcaplib.dump_pkt(pkt)
    printf("\n")

##
# @brief        Timeout handler used to break dispatch() or loop() handler
#
# @param [in]   pcap_lib    PCAP library handle
# @param [in]   pcap_if     PCAP interface handle
#
def dispatch_timeout(pcap_lib, pcap_if):
    pcap_lib.breakloop(pcap_if)

# Parse command line		
parser = OptionParser()
parser.add_option("-l", action="store_true", dest="if_list", default=False, help="Print PCAP interface list")
parser.add_option("-o", type=int, dest="dev_index", default=-1, help="Open PCAP interface given by its list index")

(options, args) = parser.parse_args()

try:	
	# Create PcapLib object
	pcaplib = PcapLib()
except PcapLibExceptionUnsupportedOS:
	printf ("Unsupported OS: %s\n", platform.system())
else:
    if_names = pcaplib.get_device_list()

    if (options.if_list == True):
        print_pcap_interface_list(if_names)
    elif (options.dev_index == -1):
        printf("\n")
        print_pcap_interface_list(if_names)
        options.dev_index = int(input("\nPlease select PCAP device by its index (first column): "))
    else:
        if ((options.dev_index >= 0) and (options.dev_index < len(if_names))):
            # Open PCAP interface denoted by index of interface list
            # for live capturing.
            p_if = pcaplib.open_live(list(if_names.keys())[options.dev_index])
            if (p_if):
                # Set filter to just capture ARP messages from remote station
                filter_str = "ether dst a0:ce:c8:0e:88:4c and ether proto 0x0806"
                pcaplib.setfilter(p_if, filter_str, 0xffffffff)

                msg = bytearray()
                msg += str("ffffffffffff").encode('utf-8')   # Destination MAC address
                msg += str("a0cec80e884c").encode('utf-8')   # Source MAC address
                msg += str("0806").encode('utf-8')           # ARP ethertype
                msg += str("0001").encode('utf-8')           # ARP hardware type
                msg += str("0800").encode('utf-8')           # ARP protocol type
                msg += str("06").encode('utf-8')             # ARP hardware address length (Ethernet = 6)
                msg += str("04").encode('utf-8')             # ARP protocol address length (IPv4 = 4)
                msg += str("0001").encode('utf-8')           # ARP operation (Request = 1)
                msg += str("a0cec80e884c").encode('utf-8')   # Sender hardware address
                msg += str("c0a80102").encode('utf-8')       # Sender prptocol address
                msg += str("000000000000").encode('utf-8')   # Target hardware address (ignored in ARP request)
                msg += str("c0a80101").encode('utf-8')       # Target protocol address

                pcaplib.sendpacket(p_if, msg, True)
                try:
                    # Call Receive handler using next_ex()
                    receive_pkt (p_if, 3000, True)
                except TimeoutError:
                    printf("Receive Timeout!\n")

                pcaplib.sendpacket(p_if, msg, True)
                # Call dispatch() with count of 1 packet
                ret_val = pcaplib.dispatch(p_if, 1, dispatch_handler, 0)
                if (ret_val == 0):
                    printf("Receive Timeout!\n")

                pcaplib.sendpacket(p_if, msg, True)
                # Call loop() with count of 1 packet
                loop_timer = threading.Timer(3.0, dispatch_timeout, args=(pcaplib, p_if,))
                loop_timer.start()
                ret_val = pcaplib.loop(p_if, 1, dispatch_handler, 0)
                if (ret_val == -2):
                    printf("Receive Timeout!\n")
                else:
                    loop_timer.cancel()

                pcaplib.sendpacket(p_if, msg, True)
                # Setup receive thread which calls dispatch() with count of 1 packet
                rx_thread = ReceiveThread(p_if)
                rx_thread.start()
                rx_thread.join()

                pcaplib.close(p_if)
