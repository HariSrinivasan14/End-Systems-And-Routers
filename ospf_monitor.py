import sys
import socket
import time
import argparse
import pickle # Used to send objects over a socket Source: https://stackoverflow.com/questions/47391774/python-send-and-receive-objects-through-sockets
from dijkstra import *

monitorInterfaceIPs = []
routerIPs = []
numRouters = 0
serverPort = 8081
routerList = []
MAX_PACKET_SIZE = 4096
OSPF_INTERVAL = 0 # Time to wait before polling for new messages

class monitorPacket:
    def __init__(self, action, table=None, interfaces=[], hasRoutingTableChanged=True):
        self.action = action # 'get' or 'set'
        self.hasRoutingTableChanged = hasRoutingTableChanged
        self.table = table # 
        self.interfaces = interfaces

def main():
    # 1. Bind the sockets & Connect to router
    routers = {} # {IP: socket}
    for i in range(numRouters):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((monitorInterfaceIPs[i], serverPort)) # Bind to 10.0.100.1:8081
        sock.connect((routerIPs[i], serverPort))        # Connect to 10.0.100.2:8081
        routers[routerIPs[i]] = sock
    
    # 2. Every so often get the tables, Djikstra's and send back
    responses = [None] * numRouters
    while True:
        totalDijkstraTime = 0.0
        recvNetworkTime = 0.0
        sendNetworkTime = 0.0

        startNetwork = time.time()
        request = monitorPacket("get")
        hasAnyRoutingTableChanged = False
        for i in range(numRouters):
            routers[routerIPs[i]].send(pickle.dumps(request))
            payload = pickle.loads(routers[routerIPs[i]].recv(MAX_PACKET_SIZE))
            if payload.hasRoutingTableChanged:
                print("[INFO] Received Routing Table From:", routerIPs[i])
                responses[i] = payload
                hasAnyRoutingTableChanged = True
        endNetwork = time.time()
        recvNetworkTime += (endNetwork - startNetwork) * 1000
        # Do not run Djikstra if no tables have changes
        if not hasAnyRoutingTableChanged:
            time.sleep(OSPF_INTERVAL)
            continue
        
        startDijkstra = time.time()
        # 3. Make a Graph & Run Djikstra
        edges = [] # [(ip1, ip2, weight)]
        interfaces = []
        for response in responses:
            for peerIP in response.table: # Routing table given to us
                if response.table[peerIP]['isDirectlyConnected'] == True:
                    # Add an Edge (Interface, IP, Weight)
                    index = peerIP.rfind(".")
                    for interface in response.interfaces:
                        interfaces.append(interface)
                        if peerIP[0:index] == interface[0:index]:
                            edges.append((interface, peerIP, 1))

            # Add 0-weight edges to the graph so all interfaces are connected
            for interface1 in response.interfaces:
                for interface2 in response.interfaces:
                    if interface1 == interface2:
                        continue
                    edges.append((interface1, interface2, 0))
    
        
        # 4. Run Dijkstra ############################################################################
        graph = build_graph(edges)
        for i in range(numRouters):
            interface = responses[i].interfaces[0]
            print("[INFO] Finding Paths For Router (" + interface + ")")
            ds, prev = dijkstra(graph, interface)

            newRoutingTable = {}

            for k in ds:
                # Skip finding the path to interfaces on the same router
                if k in responses[i].interfaces:
                    continue
                path = find_path(prev, k, edges)
                #print("{} -> {}: distance = {}, path = {}".format(interface, k, ds[k], path))
                if len(path) > 1:
                    newRoutingTable[k] = path[1]

            # 5. Send new routing tables to routers
            packet = monitorPacket("set", table=newRoutingTable)
            startTime = time.time()
            routers[routerIPs[i]].send(pickle.dumps(packet))
            endTime = time.time()
            sendNetworkTime += (endTime - startTime) * 1000

        endDijkstra = time.time()
        totalDijkstraTime = (endDijkstra - startDijkstra) * 1000
        totalDijkstraTime -= sendNetworkTime

        print("[INFO] Total Network Time:", round(sendNetworkTime + recvNetworkTime, 4), "ms")
        print("[INFO] Total Dijkstra Time:", round(totalDijkstraTime, 4), "ms")
        print("----------------------------------------------------------------------")
        time.sleep(OSPF_INTERVAL)
    # Source: https://gist.github.com/dingran/b827b65a252000e25d818ba3520242e1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='OSPF Monitor')
    parser.add_argument('-n') # Number of routers
    parser.add_argument('-s') # Starting IP address
    args = parser.parse_args()
    numRouters = int(args.n)
    
    if (not len(sys.argv) > 1):
        print("Usage: python3 simple_router.py <list of IPs to listen on>")
        exit(1)
    splitIP = args.s.split(".")
    for i in range(numRouters):
        monitorInterfaceIPs.append(splitIP[0] + "." + splitIP[1] + "." + str(int(splitIP[2])+i) + "." + splitIP[3])
        routerIPs.append(splitIP[0] + "." + splitIP[1] + "." + str(int(splitIP[2])+i) + "." + str(int(splitIP[3]) + 1))
    main()
 