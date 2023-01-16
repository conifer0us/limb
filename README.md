# limb
An Open-Source Private Linux Message Board

## Philosophy

Limb is a message board, much like Discord, except it is built to be free and open source with complete user privacy. Everyone has the right to download and use the Limb client, and anyone can host the Limb server. Anyone can see and make changes to the code that is running both of those applications. In addition, encryption is used to ensure that any message sent to a Limb Message Board is not only encrypted in transit, but also encrypted to the server. Only people who are granted access to a message board by the owner have access to the shared server key needed to share messages with others. Whether it is a fan club or just a friend from across the world, everyone is welcome, and no one's data is ever seen.

## A Custom Protocol

Limb is composed of client and server software written in python. They communicate using a custom protocol built on top of TCP that uses multiple connection types to send and receive data.

All Limb communication happens in packets that can be up to 4097B in length, meaning that your message size is limited. This is done mostly to protect the server. Your large messages will still be sent, but they will be broken up. This is so that the server can handle requests from everyone.

## Important Information

Various pieces of information are shared in Limb Connections. A few are listed below.

Server Public Key: A public RSA key used by the client to secure information transfer to the server.
Server Private Key: Used to read secure information from the client.
Client Public Key: Used by the server and by other clients to verify the sender of messages sent to the server.
Client Private Key: Used to generate signed messages by the client.
Client ID: Calculated by the sha256 sum of the client's public key. Used by the client and server to identify what communication is coming from the client. 
Username: An 8 character name that corresponds to a client.

## Limb Connection Types

Limb Connection types are extremely simple and lightweight. When a Limb connection is made from a client to a server, the first byte of the connection is read to denote the type of connection. Below, these connection types are listed and described. When you see "Connection Type x", x denotes the integer value contained in the first byte of the connection. In most cases, the rest of the connection after the first byte is encrypted with the server's public key to protect outsiders from seeing activity.

### Establish (EST): Connection Type 1

When you boot up your Limb Client, the first type of connection that occurs is Connection 1. As you will soon see, this type of connection is quite different from other types of connection in that there is no encryption applied. The first byte of this packet is simply 1, telling the server the connection type. Following the first byte is the client's PEM formatted RSA key. If the server reads this packet from the client without issue, it will respond with a single packet to the client containing its PEM formatted public key. The client will log this and use it in future communication. The server will also log the client's public key and ID (calculated from the key hash).

### Set Username (SET): Connection Type 2

#### Client Packet Crafting

If a client is establishing a connection to the server for the first time, the only thing that is known between the client and the server is the client's public key. The client still must configure it's data on the server in order to join and create message boards. The only thing left required for this is a username. Usernames are a maximum of 8 characters long and can only contain alphanumerics. In the SET connection type, the client sends a packet to the server with four parts.
1. The first byte is set to 2.
2. The client encrypts its 256 bit ID (hashed public key) with the server's public key and appends it to the end of the first byte. 
3. The chosen username is hashed and signed using the client's private key, encrypted with the server's public key, and appended to the end of the message. This produces a 512B encrypted signature.
4. The username itself is encoded with ascii, encrypted with the server's public key, and appended to the end of the message.

#### Server Message Interpretation

The server reads this packet as follows. 

1. It identifies that the connection is of type 2. 
2. It looks at the next 256 bytes, decrypts them using its private key, finds the client ID, and references its database to find the client's key. 
3. The server looks at the next 512 bytes. It decrypts those bytes to find the signature of the username using the public key found above.
4. The server uses the client's public key to decrypt the rest of the message, finding the username. The server checks the username. If the username fits the requirements and matches the signature, the client's username and signature for the username is inserted alongside the client's ID and public key in the database.
