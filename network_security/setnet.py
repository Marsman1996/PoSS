#!/usr/bin/python

from mininet.net import Mininet
from mininet.cli import CLI
from mininet.link import TCLink

def Net():
    net = Mininet(link=TCLink)
    h1 = net.addHost( 'h1')
    h2 = net.addHost( 'h2')
    h3 = net.addHost( 'h3')
    s1 = net.addSwitch( 's1' )
    c0 = net.addController( 'c0' )
    net.addLink( h1, s1, bw=10, delay='50ms' )
    net.addLink( h2, s1 )
    net.addLink( h3, s1 )
    
    net.start()
    CLI( net )

if __name__ == '__main__':
	Net()
