# limb
An Open-Source Private Linux Message Board

## Philosophy

Limb is a message board, much like Discord, except it is built to be free and open source with complete user privacy. Everyone has the right to download and use the Limb client, and anyone can host the Limb server. Anyone can see the code that is running both of those applications. In addition, encryption is used to ensure that any message sent to a Limb Message Board is not only encrypted in transit, but also encrypted to the server. Only people who are granted access to a message board by the owner have access to the shared server key needed to share messages with others. Whether it is a fan club or just a friend from across the world, everyone is welcome, and no one's data is ever seen.

## A Custom Protocol

Limb is composed of client and server software written in python. They communicate using a custom protocol that uses multiple connection types to send and receive data.

All Limb communication happens in Packets that are 4096B in length, meaning that your message size is limited. This is done mostly to protect the server. Your large messages will still be sent, but they will be broken up. This is so that the server can handle requests from everyone equally.

## Establishing A Link: Connection Type 1

When you boot up your Limb Client, the first type of connection that occurs is Connection 1. As you will soon see, this type of connection is quite different from other types of connection. In this connection, one packet is sent from the client to the server. The first byte of this packet is simply 1, telling the server the connection type. Following the first byte is the client's PEM formatted RSA key. This key is read by the server and logged in the Limb database alongside the client's key's ID. This hashed client ID will be used for the rest of the connection types. If the server reads this packet from the client without issue, it will respond with a single packet to the client containing its PEM formatted public key. The client will log this and use it in future communication. 
