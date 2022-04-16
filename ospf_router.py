import sys
import socket
import select
import pickle # Used to send objects over a socket Source: https://stackoverflow.com/questions/47391774/python-send-and-receive-objects-through-sockets
import argparse
import pprint
import time

serverInterfaceIPs = [] # IPs of router interface
monitorInterfaceIP = None
monitorSocket = None
neighborRouterIPs = [] # inputted neighbor routers
serverPort = 8081
connectionList = [] # List of socks that are connected
MAX_PACKET_SIZE = 4096
serverSockets = [] # list of interfaces we are listening on
routingTable = {} # { "10.0.1.10": {type: "client", socket: <socket>, isDirectlyConnected: true}}}
hasRoutingTableChanged = True
pp = None # Pretty printer for printing out the routing table

PRINT_ROUTING_TABLE = True

class clientPacket:
    def __init__(self, destinationIP, TTL, message, type="router", sendTime=time.time()):
        self.destinationIP = destinationIP
        self.TTL = TTL
        self.message = message
        self.type = type
        self.sendTime = sendTime

    def __str__(self):
        ret = ""
        ret += "Destination IP: " + self.destinationIP + "\n"
        ret += "TTL: " + str(self.TTL) + "\n"
        ret += "Message: " + self.message
        return ret

class monitorPacket:
    def __init__(self, action, table={}, interfaces=[], hasRoutingTableChanged = True):
        self.action = action # 'get' or 'set'
        self.hasRoutingTableChanged = hasRoutingTableChanged
        self.table = table
        self.interfaces = interfaces

def initializeNeighboringRouters(sock, interfaceIP):
    '''Take in a socket and an interfaceIP to connect to a neighboring router using.
        Returns True iff. the router was able to be connected on this interface.
    '''
    global neighborRouterIPs, routingTable, serverSockets, connectionList, hasRoutingTableChanged
    # Loop through each neighbor router and try to connect
    print("Trying to connect to IPs", neighborRouterIPs)
    for neighborRouterIP in neighborRouterIPs:
        # Connect to the neighboring router if this socket is on the same subnet
        splitIP = neighborRouterIP.split(".")
        neighborRouterIPSubnet = splitIP[0] + "." + splitIP[1] + "." + splitIP[2]
        splitIP = interfaceIP.split(".")
        sockSubnet = splitIP[0] + "." + splitIP[1] + "." + splitIP[2]
        if sockSubnet != neighborRouterIPSubnet:
            continue

        try: # Trying to connect to the neighbouring routers
            sock.connect((neighborRouterIP, serverPort))
            connectionList.append(sock)
            initPacket = clientPacket("255.255.255.255", 0, "", type="router")
            sock.send(pickle.dumps(initPacket))
            # Insert this routing into our routing table
            routingTable[neighborRouterIP] = {'socket': sock, 'type': "router", 'isDirectlyConnected': True}
            print("[INFO] Routing Table Printed Below:")
            pp.pprint(routingTable)
            # Remove this router IP from our list, since we've added it
            neighborRouterIPs.remove(neighborRouterIP)
            print("[INFO] Connected to router:", neighborRouterIP)
            hasRoutingTableChanged = True
            return True
        except Exception: # could not connect to neighboring router
            print("[WARN] Failed to connect to any routers.")
    return False

def handleMonitorRequest(sock, packet):
    ''' Process and responds accordingly to an input monitor packet and replies to the monitor
        using the provided socket. Updates the routing table using send routing table update info.
    '''
    global routingTable, serverInterfaceIPs, hasRoutingTableChanged
    reducedRoutingTable = {}
    # Remove the socket from routing table for sending to the monitor
    for ip in routingTable:
        reducedRoutingTable[ip] = {'type': routingTable[ip]['type'], 'isDirectlyConnected': routingTable[ip]['isDirectlyConnected']}

    if packet.action == "get" and hasRoutingTableChanged:
        print("[INFO] Sending Routing Table To Monitor")
        payload = monitorPacket("reply", reducedRoutingTable, serverInterfaceIPs)
        sock.send(pickle.dumps(payload))
        hasRoutingTableChanged = False
    elif packet.action == "get":
        # Tell the monitor our table has not changed
        payload = monitorPacket("reply", {}, [], False)
        sock.send(pickle.dumps(payload))
    else:
        print("[INFO] Received New Routing Table From Monitor at", time.time())
        hasRoutingTableChanged = False
        for destinationIP, nextHopIP in packet.table.items():
            if destinationIP in routingTable:
                if routingTable[destinationIP]['isDirectlyConnected'] == False:
                    routingTable[destinationIP] = {'type': 'client', 'isDirectlyConnected': False, 'socket': routingTable[nextHopIP]['socket']}
            else:
                routingTable[destinationIP] = {'type': 'client', 'isDirectlyConnected': False, 'socket': routingTable[nextHopIP]['socket']}
        
        for destinationIP in list(routingTable):
            if destinationIP not in packet.table.keys():
                routingTable.pop(destinationIP)
        
        if PRINT_ROUTING_TABLE:
            print("[INFO] Routing Table Printed Below:")
            pp.pprint(routingTable)

def main():
    global connectionList, serverSockets, neighborRouterIPs, monitorSocket, hasRoutingTableChanged, pp
    pp = pprint.PrettyPrinter(indent=4)
    # Add sockets for all of the IPs that this router should listen on
    for interfaceIP in serverInterfaceIPs:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((interfaceIP, serverPort))
        # Try to connect to any neighboring routers as a client, if fails we simply listen for them to connect to us later
        if initializeNeighboringRouters(sock, interfaceIP) is False:
            # Failed to connect to any routers. Listen on this port for clients
            sock.listen(5)
            # NOTE: Do not add socket to serverSockets if we're connecting to the other router
            serverSockets.append(sock)

    # Bind and listen on the monitor interface
    monitorSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    monitorSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    monitorSocket.bind((monitorInterfaceIP, serverPort))
    monitorSocket.listen(1)
    serverSockets.append(monitorSocket)
    monitorInterfaceIPSplit = monitorInterfaceIP.split(".")
    monitorIP = monitorInterfaceIPSplit[0] + "." + monitorInterfaceIPSplit[1] + "." + monitorInterfaceIPSplit[2] + "." + str(int(monitorInterfaceIPSplit[3])-1)
    print("Monitor IP:", monitorIP)

    while True:
        rSock, wSock, eSock = select.select(connectionList + serverSockets, [], [])
        for currentSock in rSock:
            if currentSock in serverSockets: # New Client is Connecting
                # Add a new client to the router
                sockFD, address = currentSock.accept()
                connectionList.append(sockFD)
            else:
                # Read a message from a existing client
                try:
                    message = currentSock.recv(MAX_PACKET_SIZE)
                    packet = pickle.loads(message)
                    # Add a new client/router to the routing table
                    if currentSock.getpeername()[0] == monitorIP:
                        # Monitor sent us a message
                        handleMonitorRequest(currentSock, packet)
                    elif packet.TTL == 0 and packet.destinationIP == "255.255.255.255":
                        routingTable[currentSock.getpeername()[0]] = {'socket': currentSock, 'type': packet.type, 'isDirectlyConnected': True}
                        hasRoutingTableChanged = True
                        if (packet.type == "router"):
                            print("[INFO] Router connected to us. (" + currentSock.getpeername()[0] + ") at", time.time())
                        if (packet.type == "client"):
                            print("[INFO] Client connected to us. (" + currentSock.getpeername()[0] + ") at", time.time())
                        print("[INFO] Routing Table Printed Below:")
                        pp.pprint(routingTable)
                    elif packet.TTL > 0: # Drop the packet if TTL == 0
                        # Forward the message to the host if we have that host in the forwarding table
                        if packet.destinationIP in routingTable:
                            packet.TTL = packet.TTL - 1
                            routingTable[packet.destinationIP]['socket'].send(pickle.dumps(packet))
                        else:
                            print("[WARN] Unknown Destination For Message (" + packet.destinationIP + ")")

                except Exception as e:
                    # Client has closed
                    print("[INFO] Client Disconnected. (" + currentSock.getpeername()[0] + ")")
                    routingTable.pop(currentSock.getpeername()[0], None)
                    hasRoutingTableChanged = True
                    currentSock.close()
                    connectionList.remove(currentSock)

    # References: https://www.binarytides.com/code-chat-application-server-client-sockets-python/

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='OSPF Router')
    parser.add_argument('-i', nargs="+")
    parser.add_argument('-m')
    parser.add_argument('-n', nargs="+", default="")
    args = parser.parse_args()

    if (not len(sys.argv) > 1):
        print("Usage: python3 ospf_router.py -i <list of IPs to listen on> -m <monitor interface IP> -n <peer router IP>")
        exit(1)
    for i in range(1, len(sys.argv)):
        serverInterfaceIPs = args.i
        monitorInterfaceIP = args.m
        if (args.n == ""):
            neighborRouterIPs = []
        else:
            neighborRouterIPs = args.n
    main()
    
