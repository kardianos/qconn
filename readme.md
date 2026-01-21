# qconn

qconn aims to be a hub-spoke secure transport for real-time messages.
All interfacing programs are clients. Each client may communicate with other clients as permitted by the hub.
All clients connect to a hub, which provides authentication, authorization, and encryption.
All communication between clients is encrypted and authenticated over QUIC.

Clients identify themselves using certificate fingerprints. When a client first connects, it goes through a provisioning process to obtain credentials. The client generates a private key locally and sends a certificate signing request to the server. The server signs the request and returns a certificate. This ensures private keys never leave the client machine.

Provisioning grants only the ability to obtain mTLS certificates - it does not grant communication privileges. After provisioning, clients remain in an unauthenticated state and cannot send messages to other clients. An administrator must explicitly authorize each client before it can communicate. This two-step process (provision, then authorize) ensures that even if a provisioning token is compromised, attackers cannot communicate with existing clients without administrator approval.

Each client has a hostname that must be unique among all authorized clients. When an administrator approves a client, the server checks that no other active client is using the same hostname. This check happens atomically with the authorization to prevent race conditions. If a hostname conflict is detected, the authorization fails and the client remains unauthorized. Once a client is revoked or its certificate expires, its hostname becomes available for reuse by another client.

Messages are addressed using a three-part tuple: service type, machine, and device. The service type indicates what kind of work the message relates to. The machine identifies the physical host by its certificate fingerprint. The device specifies a particular hardware unit or service instance on that machine. This addressing scheme allows flexible routing to specific endpoints across the network.

The server routes messages between clients based on role permissions. Each role defines which service types a client can provide and which types it can send messages to. Authorization checks happen on every message. A client cannot send messages to service types outside its permitted set, and it cannot receive messages for types it does not provide. Roles are managed entirely on the server side and are not embedded in client certificates.

When a message is sent, the server first locates the target machine and opens a stream to it. The target client acknowledges receipt of the message before processing it. This acknowledgment allows the server to distinguish between routing delays and processing delays. The system uses two separate timeouts: a resolution timeout for finding the target and receiving the acknowledgment, and a job timeout for waiting on the actual response after acknowledgment.

The server sends status updates back to the sender as a message progresses through the routing stages. These updates indicate when the target machine is found, when the message is forwarded, and when the target acknowledges it. This gives senders visibility into what is happening with their requests without needing to poll or guess about delays.

Certificates have short validity periods and renew automatically. Clients check their certificate expiration periodically and request renewal before expiration. This limits the window during which a revoked certificate could be misused. Once a certificate expires, any associated revocation records can be safely removed from the system.

The client maintains a persistent connection to the server and automatically reconnects if the connection drops. It handles DNS re-resolution so that if the server address changes, the client can find the new location. Connection migration allows the client to recover from network changes without losing its session state.