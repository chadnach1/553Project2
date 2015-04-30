#README
## Instructions
Use the following commands, in this order, to run our project.
```
ryu-manager localswitch.py --ofp-tcp-listen-port 6634
ryu-manager remoteswitch.py --ofp-tcp-listen-port 6635
sudo python topology.py
```
Ensure that you have Ryu and all of its requirements, as well as Mininet and OpenFlow v1.3.

The pushback service is run in the Ryu controllers. `localswitch.py` runs the
server that we are defending. We assume that only host AA_h1 will be attacked.
`remoteswitch.py` runs the pushback partner server, which is only capable of adding 
QoS policing and drop flows at the behest of our local server.