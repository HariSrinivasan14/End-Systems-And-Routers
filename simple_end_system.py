import os
import sys
import socket
import time
import pickle # Used to send objects over a socket Source: https://stackoverflow.com/questions/47391774/python-send-and-receive-objects-through-sockets


nextHopIP = "" # passed in as an argument 
nextHopPort = 8081
clientIP = "" # passed in as an argument 
clientPort = 8080
clearConsole = lambda: os.system('clear') # Source: https://stackoverflow.com/questions/517970/how-to-clear-the-interpreter-console
sock = None
connected = False
MAX_PACKET_SIZE = 4096
SLEEP_DELAY = 0.01
timeConnected = None

class clientPacket:
    def __init__(self, destinationIP, TTL, message, type="client", sendTime=""):
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


def printInitialize():
    global sock # Make the function use the global sock
    global connected, timeConnected
    if sock is not None:
        print("Resetting sock")
        sock.close()
        sock = None
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((clientIP, clientPort))
    try:
        timeConnected = time.time()
        sock.connect((nextHopIP, nextHopPort))
        initPacket = clientPacket("255.255.255.255", 0, "") 
        sock.send(pickle.dumps(initPacket))
        connected = True
    except:
        print("Could not connect to router!")
        time.sleep(1)
    return 0

def printSend():
    global sock # Make the function use the global sock
    destinationIP = input("Enter a Destination IP: ")
    message = input("Enter a message: ")
    TTL = int(input("Enter a TTL: "))
    times = int(input("Enter # of Times To Send: "))

    sendTime = str(time.time())
    messagePacket = clientPacket(destinationIP, TTL, message, "client", sendTime)
    message = pickle.dumps(messagePacket)

    for i in range(times):
        sock.send(message)
        # Sleep to ensure the socket is flushed (NOTE: We later subtract this time to get an accurate network delay)
        time.sleep(SLEEP_DELAY)


def printReceive():
    global sock # Make the function use the global sock
    global MAX_PACKET_SIZE
    times = int(input("Enter # of Messages To Receive: "))
    
    for i in range(times):
        message = sock.recv(MAX_PACKET_SIZE)
    
    packet = pickle.loads(message)
    print("Packet:", packet)

    # Calculate the time taken for the network to transfer the packet
    sendTime = float(packet.sendTime)
    receivedTime = time.time()
    timeElapsed = ((receivedTime - sendTime) - ((times - 1) * SLEEP_DELAY)) * 1e3

    print("[INFO] Time Taken:", round(timeElapsed, 2), "ms.")
    return 0

def exitClient():
    global sock # Make the function use the global sock
    if sock == None:
        exit(0)
    sock.close()
    exit(0)


def printMenu():
    res = None
    while (res not in ["1", "2", "3", "4"]):
        print("-----Main Menu-----")
        print("1: Initialize End System\n2: Send Text Message\n3: Receive Text Message\n4: Exit")
        res = input("Select Option: ")
    return int(res)

def printClientInfo():
    global connected
    print("----Simple End System----")
    print("Client IP:", clientIP)
    if connected:
        print("Router IP:", nextHopIP, " <--Connected at", timeConnected, "-->")
    else:
        print("Router IP:", nextHopIP)

def main():
    while(True):
        printClientInfo()
        option = printMenu()
        clearConsole()
        if (option == 1):  # Initialize
            printInitialize()

        elif (option == 2): # send message
            printSend()
            
        elif (option == 3): # receive message
            printReceive()
        
        else:
           exitClient() 


def sigint_handler(signal, frame):
    print("\n")
    exitClient()       

if __name__ == "__main__":
    if (not len(sys.argv) == 3):
        print("Usage: python3 simple_end_system.py <client_ip> <router_ip>")
        exit(1)
    clearConsole()
    clientIP = sys.argv[1]
    nextHopIP = sys.argv[2]
    main()
