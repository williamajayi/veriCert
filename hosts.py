import socket
import threading
from queue import Queue
import time

print_lock = threading.Lock()

# Get the node ip address by connecting to google.com and retrieving the ip address
def get_ip_addr():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("www.google.com", 80))
    return sock.getsockname()[0]

ip = get_ip_addr() #declare an ip variable

# retrieve the network portion of the ip address
net = ip[:10]
if net[-1] != ".":
    net = ip[:11]
    if net[-1] != ".":
        net = ip[:12]

net_hosts = set() # Create a non duplicate set container for the ip's
queue = Queue()

def process_hosts(net):

    # define a function to check the ip addresses on the network connected to port 5000
    def get_host_name_ip(server):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.2)
            sock.connect((server, 5000))
            with print_lock:
                net_hosts.add(server)
            sock.close()
        except:
            pass

    def threader():
        while True:
            worker = queue.get()
            get_host_name_ip(worker)
            queue.task_done()


    for x in range(100):
        t = threading.Thread(target=threader)
        t.daemon = True
        t.start()

    x = 1
    for x in range(254):
        server = net + str(x)
        if not server == ip:
            queue.put(server)

    # def start_worker():
    queue.join()

    return list(net_hosts)
    # myThread.run()
