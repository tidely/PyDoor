# Setup

## Server Setup

### Static IP

Get a static public IP address, either from your ISP or using software like [noip](https://www.noip.com/).

### Port forwarding

Setup [Port forwarding](https://en.wikipedia.org/wiki/Port_forwarding) in your router settings

### Choose server port

Choose a server port in [server.py](https://github.com/tidely/PyDoor/blob/master/server/server-cli.py)

## Client Setup

### Configure Connection

Change server host in [client.py](https://github.com/tidely/PyDoor/blob/master/client/client.py) to Server IP or URL

Change server port to Server Port

### build exe (optional)

`cd Client`
`python setup.py build`
