# qconn

qconn aims to be a hub-spoke secure transport for real-time messages.
All interfacing programs are clients. Each client may communicate with other clients as permitted by the hub.
All clients connect to a hub, which provides authentication, authorization, and encryption.
All communication between clients is encrypted and authenticated over QUIC.