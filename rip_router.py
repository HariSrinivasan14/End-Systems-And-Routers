import sys
import socket
import select
import pickle # Used to send objects over a socket Source: https://stackoverflow.com/questions/47391774/python-send-and-receive-objects-through-sockets
import argparse
import pprint
import time

PRINT_ROUTING_TABLE = True

serverInterfaceIPs = [] # IPs of router interface
neighborRouterIPs = [] # inputted neighbor routers
serverPort = 8081
connectionList = [] # List of socks that are connected
MAX_PACKET_SIZE = 4096
serverSockets = [] # list of interfaces we are listening on
routingTable = {} # { "10.0.1.10": {type: "client", socket: <socket>, isDirectlyConnected: true}}}
pp = None # Pretty printer for printing out the routing table

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

def simplifyRoutingTable(routingTable):
    ''' Simplifies the routing table for serialization over the network using pickle.
        Required because pickle is not able to seralize the socket, so we need to remove that value before sending.
    '''
    reducedRoutingTable = {}
    for ip in routingTable:
        reducedRoutingTable[ip] = {'type': routingTable[ip]['type'], 'isDirectlyConnected': routingTable[ip]['isDirectlyConnected'], 'weight': routingTable[ip]['weight']}
    return reducedRoutingTable

def broadcastRoutingTable():
    ''' Broadcasts our routing table to all neighboring directly connected routers.
    '''
    global routingTable, hasTableChanged, pp
    reducedRoutingTable = simplifyRoutingTable(routingTable)
    payload = pickle.dumps(clientPacket("255.255.255.255", 1, reducedRoutingTable, type="router"))
    for routerIP in routingTable:
        if routingTable[routerIP]['type'] == "router" and routingTable[routerIP]['isDirectlyConnected']:
            routingTable[routerIP]['sock'].send(payload)
    print("[INFO] Broadcast Routing Table Complete.")
    hasTableChanged = False

    if PRINT_ROUTING_TABLE:
        print("[INFO] Routing Table Printed Below:")
        pp.pprint(routingTable)
    return

def runBellmanFord(peerIP, peerRoutingTable):
    ''' Runs BellmanFord update to our routing table using the provided routing table from a peer.
        Sends out broadcast if any changes occur in our local routing table.
    '''
    global routingTable
    hasTableChanged = False
    print("[INFO] Updated Routing Table at", time.time())
    for destIP in peerRoutingTable:
        # If the destination is us, don't add to the routing table
        if destIP in serverInterfaceIPs:
            continue
        # Case 1 We have the IP
        if (destIP in routingTable):
            currentWeight = routingTable[destIP]['weight']
            suggestedWeight = routingTable[peerIP]['weight'] + peerRoutingTable[destIP]['weight']
            if (suggestedWeight < currentWeight):
                # Update the routing table to go through this peer instead
                routingTable[destIP]['sock'] = routingTable[peerIP]['sock']
                routingTable[destIP]['weight'] = suggestedWeight
                hasTableChanged = True
        # Case 2 We don't have this IP
        else:
            weight = routingTable[peerIP]['weight'] + peerRoutingTable[destIP]['weight']
            routingTable[destIP] = {'type': peerRoutingTable[destIP]['type'], 'isDirectlyConnected': False, 'sock': routingTable[peerIP]['sock'], 'weight': weight}
            hasTableChanged = True

    # Remove disconnected clients from table        
    for localDestIP in list(routingTable):
        nextHopIP = routingTable[localDestIP]['sock'].getpeername()[0]
        # Remove the entry from our table, if the entry is NOT is the neighboring router table anymore
        if localDestIP != peerIP and nextHopIP == peerIP and localDestIP not in peerRoutingTable:
            routingTable.pop(localDestIP)
            hasTableChanged = True

    if hasTableChanged:
        broadcastRoutingTable()
    return

def initializeNeighboringRouters(sock, interfaceIP):
    '''Take in a socket and an interfaceIP to connect to a neighboring router using.
        Returns True iff. the router was able to be connected on this interface.
    '''
    global neighborRouterIPs, routingTable, serverSockets, connectionList, ripMatrix
    # Loop through each neighbor router and try to connect
    for neighborRouterIP in neighborRouterIPs:
        # Connect to the neighboring router if this socket is on the same subnet
        splitIP = neighborRouterIP.split(".")
        neighborRouterIPSubnet = splitIP[0] + "." + splitIP[1] + "." + splitIP[2]
        splitIP = interfaceIP.split(".")
        sockSubnet = splitIP[0] + "." + splitIP[1] + "." + splitIP[2]
        if sockSubnet != neighborRouterIPSubnet:
            continue

        try: # Try to connect to the neighbouring routers
            sock.connect((neighborRouterIP, serverPort))
            connectionList.append(sock)
            initPacket = clientPacket("255.255.255.255", 0, "", type="router")
            sock.send(pickle.dumps(initPacket))
            # Insert this routing into our routing table
            routingTable[neighborRouterIP] = {'sock': sock, 'type': "router", 'isDirectlyConnected': True, 'weight': 1}
            # Broadcast the routing table
            print("[INFO] Updated Routing Table at", time.time())
            broadcastRoutingTable()
            # Remove this router IP from our list, since we've added it
            neighborRouterIPs.remove(neighborRouterIP)
            print("[INFO] Connected to router:", neighborRouterIP)
            return True
        except Exception: # could not connect to neighboring router
            print("[WARN] Failed to connect to any routers.")
    return False

def main():
    global connectionList, serverSockets, neighborRouterIPs, pp
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
                    if packet.TTL == 0 and packet.destinationIP == "255.255.255.255":
                        if (packet.type == "router"):
                            print("[INFO] Router connected to us. (" + currentSock.getpeername()[0] + ") at", time.time())
                        if (packet.type == "client"):
                            print("[INFO] Client connected to us. (" + currentSock.getpeername()[0] + ") at", time.time())

                        routingTable[currentSock.getpeername()[0]] = {'sock': currentSock, 'type': packet.type, 'isDirectlyConnected': True, 'weight': 1}
                        # Broadcast the routing table since a new client/router has connected
                        broadcastRoutingTable()
                    elif packet.destinationIP == "255.255.255.255":
                        # Received Routing Table From Another Router
                        print("[INFO] Received Routing Table From Peer")
                        runBellmanFord(currentSock.getpeername()[0], packet.message)
                    elif packet.TTL > 0: # Drop the packet if TTL == 0
                        # Forward the message to the host if we have that host in the forwarding table
                        if packet.destinationIP in routingTable:
                            packet.TTL = packet.TTL - 1
                            routingTable[packet.destinationIP]['sock'].send(pickle.dumps(packet))
                        else:
                            print("[WARN] Unknown Destination For Message (" + packet.destinationIP + ")")

                except Exception as e:
                    # Client has closed
                    print("[INFO] Client Disconnected. (" + currentSock.getpeername()[0] + ")")
                    routingTable.pop(currentSock.getpeername()[0], None)
                    # Remove any references to this socket in our routing table
                    for destionationIP in list(routingTable):
                        if routingTable[destionationIP]['sock'] == currentSock:
                            routingTable.pop(destionationIP)

                    currentSock.close()
                    connectionList.remove(currentSock)
                    broadcastRoutingTable()

    # References: https://www.binarytides.com/code-chat-application-server-client-sockets-python/

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='OSPF Router')
    parser.add_argument('-i', nargs="+")
    parser.add_argument('-n', nargs="+", default="")
    args = parser.parse_args()

    if (not len(sys.argv) > 1):
        print("Usage: python3 rip_router.py -i <list of IPs to listen on> -n <list of routers to connect to>")
        exit(1)
    serverInterfaceIPs = args.i
    if (args.n == ""):
        neighborRouterIPs = []
    else:
        neighborRouterIPs = args.n
    main()