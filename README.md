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
4. The server uses the client's public key to decrypt the rest of the message, finding the username. The server checks the username. If the username fits the requirements and matches the signature, the client's username and signature for the username is inserted alongside the client's ID and public key in the database. A table is created to store information about what message boards the client is in.

### Create Message Board (CRE): Connection Type 3

Once a client has created a username, it is easy to create a new message board using connection type 3. In this connection type, a similar packet layout is used to Connection Type 2. The first three parts of the packet serve the same purpose as the first three parts of the Connection Type 2 Packet, containing the connection type, encrypted client ID, and signature for the data in the rest of the packet.

The fourth part of the packet, however, is different than the fourth part of the packet in Connection Type 2. In Connection Type 3, the fourth part of the packet contains information about the message board being created. When crafting packets, the client creates a 128 bit AES key that will be shared only with people who are invited to join the board. This key is hashed using sha256 to create the server id. Appended to the 256 bit hashed server ID is  the name of the server encoded in ASCII with the same naming requirements as usernames. These two pieces of appended information constitute the fourth part of the packet. 

When the server receives a packet of this connection type, it will first verify the signature for the user that is specified in bytes 1 to 256. Then, it will process the fourth part of the packet to obtain a ServerID and server name. The server ID and server name will be logged alongside the creator in the database of message boards. Then, the message board created is added to the creator's database of boards to ensure that they are allowed to post on their own board. Finally, a database table dedicated to storing messages for that board is created.

### Get User Data (GETU): Connection Type 4

Now that a client has created a message board, they must invite other users to the message board, but in order to do this, the server must send some information to the client about what user they are trying to invite. Connection Type 4 allows a client to query a server for public key information about a specific username. 

The client constructs this packet in an identical way to Connection Type 2, setting the first byte to 4, encrypting its hash id, and creating a signature for the data in the fourth part of the packet. A username encrypted with the server's public key makes up the fourth part of the packet.

In response, the server will parse the username, gather the public key for that user, and return a packet that contains the user's public key, encrypted with the client's public key.

### Invite User (INV): Connection Type 5

Client 1 has just created a message board and wants to invite Client 2 to join it. To do this Client 1 can use Connection Type 5, Invite User. Before submitting a packet, however, there are a few things that have to be done. First, Client 1 has to use Connection Type 4 in order to obtain Client 2's public key. Then, Client 1 can take the obtained public key and use it to encrypt the shared server AES key. This will be referred to as the Invite Key.

Then, Client 1 can begin crafting its packet to the server. Connection Type 5's packet is laid out in a very similar way to Connection Type 2's signed packet where the first three parts of the packet are used to lay out the connection type and provide a signature. The fourth part of the packet is crafted in three parts:

1. The 256 Bit Message Board ID
2. Client 2's 256 Bit Client ID
3. Invite Key Data

When the server receives this packet, it will first ensure that the signature is correct for the packet and that Client 1, submitting the invite, is the owner of the specified server. Then, the server will add the server to Client 2's Boards Database along with the Invite Key. When this invitation is stored in Client 2's Boards database, SQL automatically assigns an ID number to that invite. This will be used in the next connection.

### Get Invite (GETI): Connection Type 6

Once Client 1 has added Client 2 to a message board, Client 2 has to be able to retrieve their key. This is what Connection Type 6 is for. In Connection 6, a client crafts a signed packet much like the previous packets. In the fourth part of the packet is the ID number of the invitation being queried. Invitation IDs on the server increment sequentially. Only one invitation is served from the server per connection. If there is no invitation in that ID slot, a blank packet is returned.

When the server returns board information for the user, it is encrypted with the client's public key and ordered in the following way:

1. The 256 bit server ID number
2. The 256 byte signed server key that is encrypted with the client's public key
3. The name of the server, encoded in ascii

The client can then read and store this information its database of message boards. 

### Post Message (POST): Connection Type 7

### Get Message (GETM): Connection Type 8