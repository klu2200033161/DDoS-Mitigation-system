from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel

def topology():

    net = Mininet(controller=RemoteController)

    c0 = net.addController('c0', ip='127.0.0.1', port=6633)

    h1 = net.addHost('h1')
    h2 = net.addHost('h2')
    h3 = net.addHost('h3')

    s1 = net.addSwitch('s1')

    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)

    net.start()

    print("Network started")

    CLI(net)

    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    topology()