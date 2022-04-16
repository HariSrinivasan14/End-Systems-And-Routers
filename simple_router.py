import sys
import socket
import select
import pickle # Used to send objects over a socket Source: https://stackoverflow.com/questions/47391774/python-send-and-receive-objects-through-sockets
import argparse

serverInterfaceIPs = []
serverPort = 8081
connectionList = []
MAX_PACKET_SIZE = 4096

routingTable = {}

class clientPacket:
    def __init__(self, destinationIP, TTL, message, sendTime, type="client"):
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

def main():
    global connectionList
    serverSockets = []
    # Add sockets for all of the IPs that this router should listen on
    for serverIP in serverInterfaceIPs:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((serverIP, serverPort))
        sock.listen(5)
        serverSockets.append(sock)
        connectionList.append(sock)

    while True:
        rSock, wSock, eSock = select.select(connectionList, [], [])
        
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
                    if packet.TTL == 0 and packet.destinationIP == "255.255.255.255":
                        print("[INFO] New Client Connected (" + currentSock.getpeername()[0] + ")")
                        routingTable[currentSock.getpeername()[0]] = currentSock
                    elif packet.TTL > 0: # Drop the packet if TTL == 0
                        # Forward the message to the host if we have that host in the forwarding table
                        if packet.destinationIP in routingTable:
                            packet.TTL = packet.TTL - 1
                            routingTable[packet.destinationIP].send(pickle.dumps(packet))
                        else:
                            print("[WARN] Unknown Destination For Message (" + packet.destinationIP + ")")

                except Exception as e:
                    # Client has closed
                    print("[INFO] Client Disconnected (" + currentSock.getpeername()[0] + ")")
                    routingTable.pop(currentSock.getpeername()[0], None)
                    currentSock.close()
                    connectionList.remove(currentSock)

    # References: https://www.binarytides.com/code-chat-application-server-client-sockets-python/

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Simple Router')
    parser.add_argument('-i', nargs="+")
    args = parser.parse_args()

    if (not len(sys.argv) > 1):
        print("Usage: python3 simple_router.py -i <list of IPs to listen on>")
        exit(1)
    serverInterfaceIPs = args.i
    main()
