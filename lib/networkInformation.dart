// Importing core libraries
import 'dart:async';
//import 'dart:collection';
//import 'dart:core';
import 'dart:io';
//import 'dart:convert';
import 'dart:typed_data';

// Importing libraries from external packages
//import 'package:flutter_webrtc/flutter_webrtc.dart';
//import 'package:http/http.dart' as http;

// Importing libraries from our packages
//import 'package:b4connection/B4connection.dart';
import 'udpPkg.dart';
//import 'package:b4rttable/routingmanager.dart';
//import 'endPointAddress.dart';
/*
// A Queue to act as the RM buffer
Queue<List> rmBufferQueue = Queue<List>();
// A Queue to act as the IM buffer
Queue<List> imBufferQueue = Queue<List>();
// A Queue to act as the CM Internal buffer
Queue<List> cmInternalBufferQueue = Queue<List>();
*/
// A class for node to node communication.
class NetworkDetails {

    // For each of the other nodeIDs,
    // a separate connection instance is to be created, as connections are bound to nodeIDs of the other nodes.

    // Private static instance of the CommunicationManager
    static final NetworkDetails _instance = NetworkDetails._internal();

    // Private constructor
    NetworkDetails._internal();

    // Factory constructor to access the singleton instance
    factory NetworkDetails() {
        return _instance;
    }
 //   bool useProxy = false;
/*    Socket? _socket;
    Socket? _localSocket;

    int proxy4layerID=6;
    int proxy6layerID=7;
    int proxyDual46layerID=8;

  //  ProxyEndpointAddress proxy4add, proxy6add;
 //   ICECandidates directadd;
*/
// Asynchronous function to get endpoint information list. It used stun server and stun port, bootstrapserver to create IPv4 and IPv6 UDP
// stunServer is a DNS name. It can be resolved to both IPv4 and IPv6 depending on how the stunServer is configured.
// We should try to use stunServer which has both IPv4 and IPv6 addresses.
    //Future <List<List<dynamic>>> getNetworkInfo(String nodeID, String bootstrapServer, String stunServer, int stunPort) async {
    Future <List<List<dynamic>>> getNetworkInfo(String stunServer, int stunPort) async {

        // Initialize an empty list to store information about active IPs
        List<List<dynamic>> activeIPInfo = [];
        try {

            // Retrieve a list of network interfaces, excluding link-local and loopback addresses
            List<dynamic> actIPList=await getActiveIPList(await NetworkInterface.list(includeLinkLocal: false,includeLoopback: false));

            // Iterate through each address in the active IP list
            for(var address1 in actIPList) {

                // Get the IP address and its type (IPv4 or IPv6)
                String ip = address1.address;
                String ipType = address1.type == InternetAddressType.IPv6 ? "IPv6" : "IPv4";

                // Determine if the IP address is private (i.e., within a private network range)
                String isPrivate = isPrivateIP(ip) ? "Yes" : "No";

                // Initialize variables to hold public IP and port information, NAT status, and NAT type
              /*  bool? behindNAT;
                int? publicPort;
                String? natType;

               */
                int? publicPort;
                String? publicIP;

                // If the IP address is private, try to get the public IP using the STUN server
                if(isPrivate.startsWith("Y")) {

                    // Handle public IP fetching for IPv4 and IPv6 differently
                    // Check the IP type (IPv4 or IPv6)
                    if (ipType == "IPv4") {

                        // If the IP type is IPv4, call the getPublicIP function to retrieve public IP and port
                        Map<String, dynamic> publicIPResp = await getPublicIP(stunServer, stunPort);

                        // Assign the retrieved public IP and port to respective variables
                        publicIP = publicIPResp['publicIP'];
                        publicPort = publicIPResp['publicPort'];
                    }
                    else if (ipType == "IPv6") {

                        // If the IP type is IPv6, call the getPublicIP6 function to retrieve public IP and port
                        Map<String, dynamic> publicIPResp = await getPublicIP6(stunServer, stunPort);

                        // Assign the retrieved public IP and port to respective variables
                        publicIP = publicIPResp['publicIP'];
                        publicPort = publicIPResp['publicPort'];
                    }
                 /*
                    useProxy = true;
                    
                    // connect to bootstrap and get the list of proxy server (RT of proxy layer)
                    // find the closest proxy server node. Recursively,
                    // get the proxy server RT from current closest and find the closest Proxy server node in it.
                    // Repeat the above process till we get the closest proxy server
                    //bootstrapServer = proxy['ip'] + ':' + proxy['port'].toString();
                    //pnode = proxy['ip'] + ':' + proxy['port'].toString();
                    String pnode=findClosestProxyNodeRecursively(bootstrapServer, Proxy4layerID) as String;

                    // get the proxy server's ip address and port to be used in endpoint address of current node.

                    // Find the index of the last colon
                    int lastColonIndex = pnode.lastIndexOf(':');
                    // String before the last colon
                    String part1 = pnode.substring(0, lastColonIndex);
                    // String after the last colon
                    int part2 = pnode.substring(lastColonIndex + 1) as int;
                    //get the ip address type
                    String addtype=getAddressType(part1);
                     // set endpoint address for self node

                    // Create the TCP connection and set the proxy true with proxy ip and port.
                    _socket=connect(part1, part2) as Socket?;
                    // The proxy node, will enter the TCP socket pointer, the current nodes nodeID in the proxy forwarding table.
                   
                    _socket!.listen(_messageHandler);
*/
                    // Ensure that a messageHandler is registered with TCP socket to received the incoming bytes and parse the received messages.
                }
// TBD - 20250225-1914 : proxy forwarding table related protocol on a TCP server socket is to be created.
                // If the IP address is not private, treat it as a public IP
                
                else if(isPrivate.startsWith("N")) {
                    publicIP=ip;

                    // For IPv4 and IPv6, bind a UDP socket to determine the public port
                    if(ipType == "IPv4") {
                  //      String ipadd4=InternetAddress.anyIPv4 as String;
                        UDPSocket myServer = await UDPSocket.bind(InternetAddress.anyIPv4, 0);
                        publicPort = myServer.rawSocket.port;
               /*         _socket=await connect(ipadd4, publicPort);
                        _socket!.listen(_messageHandler);
                   //     myServer.handler((message){   });
*/
                    } else if(ipType == "IPv6") {
                    //    String ipadd6=InternetAddress.anyIPv6 as String;
                        publicPort =
                            (await UDPSocket.bind(InternetAddress.anyIPv6, 0))
                            .rawSocket.port;
                 /*       _socket=await connect(ipadd6, publicPort);
                        _socket!.listen(_messageHandler);
                        */

                    }
                }

                // Add the collected data for each IP: [IP type, IP address, private status, public IP, public port]
                activeIPInfo.add([ipType, ip, isPrivate, publicIP,publicPort]);

            }//for2

        } catch (e) {
            // Catch and print any errors that occur during execution
            print('Error: $e');
        }
        // Return the final list of IP information
        return activeIPInfo;
    }

// Asynchronous function to get a list of active IP addresses from given network interfaces
    Future<List<dynamic>> getActiveIPList( List<NetworkInterface> interfaces) async {

        // List to hold the active IP addresses.
        List<dynamic> internetIPs = [];

        // Iterate over each network interface.
        for (var interface in interfaces) {

            // Iterate over each address of the current network interface.
            for (var addr in interface.addresses) {
                try {

                    // Attempt to establish a socket connection to Google's public DNS server (8.8.8.8) on port 53.
                    // Set a timeout of 5 seconds for the connection attempt.
                    Socket socket = await Socket.connect(
                        '8.8.8.8',
                        53,
                        sourceAddress: addr.address,
                        timeout: Duration(seconds: 5),
                    );

                    // If the connection is successful, destroy the socket (close the connection).
                    socket.destroy();

                    // Add the current address (IP) to the list of active IPs.
                    internetIPs.add(addr);
                } catch (e) {

                    // If an error occurs (e.g., unable to connect), catch the exception and do nothing.
                    // This allows the code to continue checking the next address without failure.
                }
            }
        }

        // Return the list of active IP addresses.
        return internetIPs;
    }

    // Function to check if an IP address is private (indicating NAT)
    bool isPrivateIP(String ip) {

        // List of private IP ranges for both IPv4 and IPv6
        final privateRanges = [
                                  '10.', '172.16.','172.17.','172.18.','172.19.','172.20.','172.21.','172.22.','172.23.','172.24.','172.25.','172.26.','172.27.','172.28.','172.29.','172.30.','172.31.', '192.168.', // Private IPv4 ranges
                                  'fc00::', 'fd00::' // Private IPv6 ranges
                              ];

        // Iterate through the private IP ranges
        for (var range in privateRanges) {

            // If the IP starts with any of the private ranges, return true (it's a private IP)
            if (ip.startsWith(range)) {

                // NAT detected true (private IP)
                return true;
            }
        }

        // If the IP does not match any of the private ranges, return false (it's a public IP)
        return false; // Public IP
    }

    // Function to get the public IP and port using a STUN server
    Future<Map<String, dynamic>> getPublicIP(String stunServer, int stunPort) async {

        // Bind a raw datagram socket to any available IPv4 address and an ephemeral port
        final socket = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 0);

        // Generate a unique transaction ID for the STUN message
        final transactionId = List<int>.generate(12, (i) => i);

        // Create the STUN message (Binding Request) with the transaction ID
        final stunMessage = Uint8List.fromList([
         0x00, 0x01, // Message type: Binding Request
         0x00, 0x00, // Length: 0 (no additional attributes)
         0x21, 0x12, 0xA4, 0x42, // Magic Cookie
         ...transactionId, // Transaction ID
                                               ]);

        // Look up the STUN server address (resolve domain name to IP) and Ensure IPv4 address
        final stunServerAddress = (await InternetAddress.lookup(stunServer))
        .where((addr) => addr.type == InternetAddressType.IPv4)
        .toList();

        // If STUN server address resolution fails, return null for public IP and port
        if (stunServerAddress.isEmpty) {
            print('Failed to resolve STUN server address.');
            return {'publicIP': null, 'publicPort': null};
        }

        // Get the first IPv4 address of the STUN server
        final stunServerIP = stunServerAddress.first;

        // Send the STUN message (Binding Request) to the STUN server
        socket.send(stunMessage, stunServerIP, stunPort);

        // Declare a variable to hold the public ip and public port
        String? publicIP;
        int? publicPort;

        // Wait for the STUN response asynchronously

        // Wait for events from the socket (e.g., reading incoming data).
        await for (var event in socket) {
            // Check if the event is a "read" event, which means we have received data.
            if (event == RawSocketEvent.read) {
                // Receive the incoming datagram (network packet).
                final datagram = socket.receive();
                // If a datagram is received (i.e., not null), process its data.
                if (datagram != null) {
                    // Extract the response data from the datagram.
                    final response = datagram.data;
                    // Ensure that the response data length is greater than 20 bytes (to ensure valid data).
                    if (response.length > 20) {
                        // Extract the address family from the response (byte 25).
                        final addressFamily = response[25];
                        // Check address family (IPv4 or IPv6). If it's an IPv4 response (address family 0x01)
                        if (addressFamily == 0x01) { // IPv4
                            // Extract public port using the XOR of response data and magic cookie
                            final magicCookie = [0x21, 0x12, 0xA4, 0x42];
                            // Extract the public port from the response (bytes 26 and 27).
                            // The port is XOR-ed with the magic cookie for additional obfuscation.
                            publicPort = (response[26] << 8 | response[27]) ^
                                         (magicCookie[0] << 8 | magicCookie[1]);
                            // Parse the public IP address from bytes 28 to 31, XOR-ing with the magic cookie.
                            // This is required because the STUN protocol obfuscates the IP address using the magic cookie.
                            final ip = [
                                           response[28] ^ magicCookie[0],
                                           response[29] ^ magicCookie[1],
                                           response[30] ^ magicCookie[2],
                                           response[31] ^ magicCookie[3],
                                       ].join('.');
                            // The final parsed public IP is stored in the `publicIP` variable.
                            publicIP = ip;
                        } else {
                            // Print an error if the response is not IPv4
                            print('Received a non-IPv4 response.');
                        }
                    } else {
                        // Print an error if the STUN response is invalid (too short)
                        print('Invalid STUN response.');
                    }
                }
                // Exit the loop once a valid response is received
                break;
            }
        }
        // Close the socket after receiving the response
        socket.close();
        // Return the public IP and port in a map
        return {
                'publicIP':            publicIP,
                'publicPort':            publicPort,
        };
    }

    // Gets public IPv6 address and port using STUN server
    //Future<String?> getPublicIPv6(String stunServer, int stunPort) async {
    Future<Map<String, dynamic>> getPublicIP6(String stunServer, int stunPort) async {
        // try {
        // Construct STUN binding request for IPv6
        final socket = await RawDatagramSocket.bind(InternetAddress.anyIPv6, 0);// Bind to any available IPv6 address and port
        // STUN binding request in raw bytes (specific to the STUN protocol)
        final request = [
        0x00, 0x01,  // Message Type: Binding Request (0x0001)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        ];
        // Generate random transaction ID for the request
        final transactionId = List<int>.generate(12, (index) => index);
        // Append transaction ID
        request.addAll(transactionId);

        // Resolve the STUN server address (IPv6) by performing a DNS lookup for the given STUN server name.
        final stunServerAddress = (await InternetAddress.lookup(stunServer))
        .where((addr) => addr.type == InternetAddressType.IPv6)
        .toList();

        // Check if the STUN server address was resolved. If not, return null.
        if (stunServerAddress.isEmpty) {
            print('Failed to resolve STUN server address.');
            // Return a map with null values for public IP and port, indicating that the STUN server could not be reached.
            return {'publicIP': null, 'publicPort': null};
        }
        // Retrieve the first resolved IPv6 address of the STUN server.
        final stunServerIP = stunServerAddress.first;

        // Send the STUN request to the resolved STUN server IP address and port using the UDP socket.
        //  socket.send(Uint8List.fromList(request), InternetAddress(stunServer), stunPort);
        socket.send(Uint8List.fromList(request), stunServerIP, stunPort);

        // Wait for a response from the STUN server using the socket.
        final response = await socket.receive();
        // Declare variables to store the public IP and port extracted from the response.
        String? ip;
        int? port;
        // Check if a response was received from the STUN server.
        if (response != null) {
            // Parse the response and extract the public IP address
            // STUN response format includes the public IP address in the message
            // The public address is typically in the 'MAPPED-ADDRESS' field.


            // Extract the public IP address from the response.
            ip = response.address.address;
            // Extract the public port from the response.
            port = response.port;
            // Print the public IP and port to the console for debugging.
            print('Public IP: $ip');
            print('Public port: $port');

            //return ip;
        }
        //  } catch (e) {
        //    print('Error: $e');
        // }
        //return null;
        // Close the socket after receiving the response
        socket.close();
        // Return public IP and port as a map
        return {
                'publicIP':            ip,
                'publicPort':            port,
        };
    }

// Transaction ID for the STUN request, this should be unique for each request ideally, used for IPv6 requests
    final Uint8List transactionIDIpv6 = Uint8List.fromList([
                                         0x63, 0x43, 0xF6, 0x22, 0x11, 0xA1, 0x47, 0x37, 0x00, 0x00, 0x00, 0x00,
                                     ]);
    // Declare the socket for IPv6 and variables for storing public IP and port
    UDPSocket? _socketIpv6;
    late String srip6;
    late int srport6;


    // Function to send a STUN request and get the public IPv6 address
    //Future<void> sendStunRequestIpv6(String stunServer,int Port) async {
    Future<Map<String, dynamic>?>getPublicIPv6(String stunServer,int Port) async {
        // Bind to any available IPv6 address and any port
        _socketIpv6 = await UDPSocket.bind(InternetAddress.anyIPv6, 0);
        print('bound to ipv6');

        // Create a STUN Binding Request with the STUN header and Magic Cookie
        var stunRequest = Uint8List.fromList([
         0x00, 0x01, 0x00, 0x00, // STUN Binding Request Header
         0x21, 0x12, 0xA4, 0x42, // Magic Cookie
                                             ]) + transactionIDIpv6; // Append the transaction ID
        // Lookup the STUN server to get its IPv6 address
        final stunServerAddress = (await InternetAddress.lookup(stunServer))
        .where((addr) => addr.type == InternetAddressType.IPv6)
        .toList();
// If the STUN server address could not be resolved, print an error message
// and return null
        if (stunServerAddress.isEmpty) {
            print('Failed to resolve STUN server address.');
            // return {'publicIP': null, 'publicPort': null};
        }
// Use the first resolved IPv6 address of the STUN server
        final stunServerIP = stunServerAddress.first;
        //check socket is not null
        if (_socketIpv6 != null) {
            // Send the STUN request to the STUN server using the resolved IPv6 address.
            await _socketIpv6!.send(stunRequest, stunServerIP, Port);
            //   await _socketIpv6!.send(stunRequest, stunServer, Port);
            //  Wait for the response from the STUN server, with a timeout of 5000ms (5 seconds).
            Datagram? datagram = await _socketIpv6!.receive(
                timeout: 5000); // Timeout set to 5000ms
            // Check if a response is received and if it has enough data to process (at least 20 bytes, typical for STUN responses)
            if (datagram != null && datagram.data.length >= 20) {
                // Extract the response data from the received datagram
                var response = datagram.data;
                // Check if the response header indicates a successful Binding Response (STUN success response)
                if (response[0] == 0x01 &&
                        response[1] == 0x01) { // Binding Response Success
                    // If the response is valid, parse it using a custom method (_parseResponseIpv6)
                    _parseResponseIpv6(response);
                }
                // Close the socket after receiving the response
                _socketIpv6?.close();
                // Return the public IP and port as a map after parsing the response
                return {
                    'publicIP':     srip6, // srip6 should have been set in the parsing method
                    'publicPort':   srport6, // srport6 should have been set in the parsing method

                };
            } else {
                // If no valid response is received or the response doesn't have enough data, print an error
                print('No response or invalid response received from STUN server');
            }
        }
        // Return null if no valid response received
        return null;
    }

    // Function used to parse the response from the STUN server and extract public IPv6 address and port
    void _parseResponseIpv6(Uint8List response) {
        // Offset for the magic cookie in the STUN response (4 bytes)
        int magicCookieOffset = 4;

        // Extract magic cookie from the response, which is used to XOR the address and port later
        Uint8List magicCookie = response.sublist(
                                    magicCookieOffset, magicCookieOffset + 4);

        // The message length is stored in the next 2 bytes (position 2 and 3 in the response)
        int messageLength = (response[2] << 8) + response[3];
        // The starting index for parsing attributes (attributes start from byte 20 in the response)
        int index = 20;
        // Loop through the attributes in the STUN response
        while (index < 20 + messageLength) {
            // The first 2 bytes represent the attribute type
            int type = (response[index] << 8) + response[index + 1];
            // The next 2 bytes represent the length of the attribute's value
            int length = (response[index + 2] << 8) + response[index + 3];
            // Move the index past the attribute header (4 bytes for type + length)
            index += 4;
            // Check if the attribute type is MAPPED-ADDRESS (0x0001) or XOR-MAPPED-ADDRESS (0x0020)
            if (type == 0x0001 ||
                    type == 0x0020) { // MAPPED-ADDRESS or XOR-MAPPED-ADDRESS
                // The family field (byte after the type) tells whether the address is IPv4 or IPv6
                int family = response[index + 1];
                // The port is stored in the next 2 bytes and is XORed with part of the magic cookie
                int port = ((response[index + 2] << 8) +
                            response[index + 3]) ^ (magicCookie[0] << 8 | magicCookie[1]);
                // Declare a variable for the address (we will parse it based on the family)
                InternetAddress address;
                // Check if the address family is IPv6 (0x02)
                if (family == 0x02) { // IPv6
                    // Prepare a list to store the 16-byte XORed address
                    List<int> xorAddr = List<int>.filled(16, 0);
                    // The XOR key consists of the magic cookie and the transaction ID for this request
                    List<int> xorKey = List.from(magicCookie)
                                       ..addAll(transactionIDIpv6);

                    // XOR each byte of the address with the XOR key to obtain the IPv6 address
                    for (int i = 0; i < 16; i++) {
                        xorAddr[i] = response[index + 4 + i] ^ xorKey[i % xorKey.length];
                    }

                    // Declare a list of type String to hold the hexadecimal parts of the IPv6 address
                    var addrHexParts = <String>[];

                    // Convert each byte to its hexadecimal representation.
                    //  and XORed address to a valid IPv6 string
                    for (int i = 0; i < xorAddr.length; i += 2) {
                        addrHexParts.add(xorAddr.sublist(i, i + 2).map((b) =>
                                         b.toRadixString(16).padLeft(2, '0')).join());
                    }

                    // Join all hexadecimal parts into a full IPv6 address string
                    var addressString = addrHexParts.join(':');

                    try {
                        // Convert the address string into an InternetAddress object
                        address = InternetAddress(addressString);
                        // Store the public IPv6 address
                        srip6=address.toString();
                        // Store the public port
                        srport6=port;
                        //   _publicIPv6 = address;
                        //   _publicPortIPv6 = port;
                        print('Public IP6: $address');
                        print('Public port6: $port');

                    } catch (e) {
                        // If the address is not valid, print the error
                        print("Error creating InternetAddress from IPv6: $e");
                    }
                }
                // Move to the next attribute, adjusting for potential error in original loop increment
                index += length;
            } else {
                // Ensure we correctly skip over unrecognized attributes
                index += length;
            }
        }
    }
/*
    // Utility function to find the closest node based on XOR distance
    //closestNode = proxy['ip'] + ':' + proxy['port'].toString();
    String findClosestFromPRT(String nodeId, List<Map<String, dynamic>> proxyRoutingTable) {
        String closestNode = '';
        int closestDistance = 160; // Max distance for 160-bit node ID

        for (var proxy in proxyRoutingTable) {
            String proxyNodeId = proxy['node_id']; // 160-bit hexadecimal node ID
            int distance = calculateDistance(nodeId, proxyNodeId);

            if (distance < closestDistance) {
                closestDistance = distance;
                closestNode = proxy['ip'] + ':' + proxy['port'].toString();
            }
        }

        return closestNode;
    }

    // Function to calculate XOR distance between two node IDs
    int calculateDistance(String nodeId, String proxyNodeId) {
        // Convert hex node IDs to BigInt for comparison
        BigInt nodeBigInt = BigInt.parse(nodeId, radix: 16);
        BigInt proxyBigInt = BigInt.parse(proxyNodeId, radix: 16);
        int dist=(nodeBigInt ^ proxyBigInt).toInt();
        return dist; // XOR and convert to integer distance
    }

    // Main loop to iteratively find the closest node
    //closestNode = proxy['ip'] + ':' + proxy['port'].toString();
    Future<String> findClosestProxyNodeRecursively(String bootstrapServer, int Proxy4layerID) async {
        // Start with the Bootstrap Server (BS) as the closest node
        String closest = bootstrapServer;
        String cnode = '';

        do {
            cnode = closest;
            print('Current Node: $cnode');

            // Get the routing table for the Proxy4LayerID from the current closest node
            //List<Map<String, dynamic>> routingTable = await routingtable.getRT(Proxy4layerID, node);
            List<Map<String, dynamic>> proxyRoutingTable = await RoutingManager.getRT(cnode, Proxy4layerID);
            //getRT(Proxy4layerID, node);
            // Find the closest node from the routing table
            closest = findClosestFromPRT(selfNodeID, proxyRoutingTable);
            print('Closest Node: $closest');

        } while (cnode != closest); // Repeat until convergence

        print('Final Closest Node: $closest');
        return closest;
    }

    // Connect to this proxy server and return the socket.
    Future<Socket> connect(String proxyIP, int proxyPort) async {
        return await Socket.connect(proxyIP, proxyPort);
    }

    // Message handler to process incoming messages from the proxy
    void _messageHandler(List<int> data) {
        String message = utf8.decode(data);
        String selfNodeHash=;
        print("Received message from proxy: $message");

        try {
            var decodedMessage = jsonDecode(message);
            if (decodedMessage is List) {
                // get the destination hash
                String dhash = decodedMessage[0] ;
                print("Destination Module: $dhash");
                //match the destination hash with self node hash
                if (dhash == "selfNodeHash") {
                    //if destination hash matched with node
                    //get the destination module
                    String dmodule = decodedMessage[1] ?? 'Unknown Module';
                    print(
                        "Received a destination module name: ${decodedMessage[1]}");
                    print("Destination Module: $dmodule");

                    // Handle specific module actions
                    if (dmodule == 'RM') {
                        //put message to RM buffer
                        rmBufferQueue.add(message as List);
                    } else if (dmodule == 'IM') {
                        //put message to IM buffer
                        imBufferQueue.add(message as List);
                    }
                }else {
                    //if destination hash not matched with node
                    //get the next hop hash from rm for destination node
                    nexthop=RoutingManager.nextHop() ;
                    //get the next hop hash
                    nexthophash= nexthop.EndpointAddress.nodeID;

                    //set the next hop hash as destination hash in message

                    //put this message to cm send buffer to sending to the next hop
                    cmInternalBufferQueue.add(message as List);
                }
            } else {
                print("Message format is invalid: $message");
            }
        } catch (e) {
            print("Error processing message: $e");
        }
    }
*/
    // Function to check if an IP address type
    String getAddressType(String address) {
      // Check if it's IPv4
      if (isIPv4(address)) {
            return 'IPv4';
        }

      // Check if it's IPv6
      else if (isIPv6(address)) {
        // Check if the IPv6 is in the private range (ULA) or loopback
            return 'IPv6';
      }
      return 'Invalid address';
    }

    // Check if the address is a valid IPv4
    bool isIPv4(String address) {
      final ipv4Regex = RegExp(r'^(\d{1,3}\.){3}\d{1,3}$');
      return ipv4Regex.hasMatch(address);
    }

    // Check if the address is a valid IPv6
    bool isIPv6(String address) {
      final ipv6Regex = RegExp(r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$');
      return ipv6Regex.hasMatch(address);
    }
    
  /*
                extra code
                     EndpointAddress endpoint = pnode.endpointAddress;
                    if (endpoint.publicipv6 != null && endpoint.publicipv6port != null) {
                        print('IPv6 Address: ${endpoint.publicipv6}');
                        ipv6add=endpoint.publicipv6;
                        print('IPv6 Port: ${endpoint.publicipv6port}');
                        ipv6port=endpoint.publicipv6port;
                      } else if (endpoint.publicipv4 != null && endpoint.publicipv4port != null) {
                        print('IPv4 Address: ${endpoint.publicipv4}');
                        ipv4add=endpoint.publicipv4;
                        print('IPv4 Port: ${endpoint.publicipv4port}');
                        ipv4port=endpoint.publicipv4port;
                      } else {
                        print('IPv4 Address or Port not available.');
                      }

        // Determines the NAT type by performing multiple NAT tests using a STUN server
    Future<String> determineNATType(String stunServer, int stunPort) async {
        try {
            // Perform NAT tests and determine the NAT type
            String natType = await _performNATTests(stunServer, stunPort);
            return natType;
        } catch (e) {
            // If an error occurs, print the error message
            print("Error determining NAT Type: $e");
        }
        // Return 'Null' if any error occurs
        return "Null";
    }

    // Performs various NAT tests to determine the NAT type using a STUN server
    Future<String> _performNATTests(String stunServer, int stunPort) async {
        // Test I: Send request without changing IP or port
        String mappedAddressTest1 = await _stunTest(stunServer, stunPort, changeIP: false, changePort: false);
        if (mappedAddressTest1.isEmpty) {
            // If no address is mapped, return "No UDP connectivity"
            return "No UDP connectivity";
        }

        // Parse the mapped address from Test I
        var parts = mappedAddressTest1.split(':');

        // Check if the response format is valid
        if (parts.length != 2) return "Invalid response in Test I";
        String publicIP1 = parts[0];
        int publicPort1 = int.parse(parts[1]);

        // List network interfaces and check if the device is behind NAT
        List<NetworkInterface> interfaces = await NetworkInterface.list();
        bool isNatted = true;

        // Iterate over each network interface.
        for (var interface in interfaces) {
            // Iterate over each address of the current network interface.
            for (var address in interface.addresses) {
                // If the public IP matches an interface IP, it's not behind NAT
                if (address.address == publicIP1) {
                    isNatted = false;
                    break;
                }
            }
        }

        // If not behind NAT, return "No NAT"
        if (!isNatted) {
            return "No NAT";
        }

        // Test II: Changing both IP and port
        String test2Response = await _stunTest(stunServer, stunPort, changeIP: true, changePort: true);
        // If the response is not empty, it indicates a Full Cone NAT. In this case, the NAT allows any external host to send data to the internal host.
        if (test2Response.isNotEmpty) {
            return "Full Cone NAT";
        }

        // Test III: Changing only the port
        String test3Response = await _stunTest(stunServer, stunPort, changeIP: false, changePort: true);
        // If the response is not empty, it indicates a Restricted Cone NAT. This type of NAT restricts incoming traffic to the internal host only from addresses that the internal host has previously sent data to.
        if (test3Response.isNotEmpty) {
            return "Restricted Cone NAT";
        }

        // Re-running Test I to check for Symmetric NAT
        String mappedAddressTest1Again = await _stunTest(stunServer, stunPort, changeIP: false, changePort: false);
        // If the mapped address changes between the first and second test, it indicates a Symmetric NAT. Symmetric NAT assigns a different public port for each external host.
        if (mappedAddressTest1Again != mappedAddressTest1) {
            return "Symmetric NAT";
        }
        // If none of the above conditions are met, it must be Port Restricted Cone NAT.
        // This type of NAT behaves similarly to Restricted Cone NAT, but it also restricts incoming traffic based on both IP and port.
        return "Port Restricted Cone NAT";
    }
    // Magic cookie for STUN requests
    final _magicCookie = [0x21, 0x12, 0xA4, 0x42];

    // Performs a STUN test to get the public IP and port using stun server
    Future<String> _stunTest(String stunServer, int stunPort, {bool changeIP = false, bool changePort = false}) async {
        // Bind socket to any IPv4 address and port
        final socket = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 0);
        // Generate transaction ID and construct STUN request message
        final transactionId = List<int>.generate(12, (i) => i);
        final stunMessage = Uint8List.fromList([
         0x00, 0x01, // Message Type: Binding Request
         0x00, 0x08, // Message length
         ..._magicCookie, // Magic cookie
         ...transactionId, // Transaction ID
         0x00, 0x03, // Message Attributes
         0x00, 0x04, // Change IP and/or port flags
         0x00, 0x00, 0x00, (changeIP ? 0x04 : 0x00) | (changePort ? 0x02 : 0x00), // Flags to indicate if IP/Port should change
                                               ]);

        // Resolve the STUN server's address using the domain name (stunServer) and filter for IPv4 addresses.
        final stunServerAddress = (await InternetAddress.lookup(stunServer))
        .where((addr) => addr.type == InternetAddressType.IPv4)
        .toList();
        // If no valid IPv4 address is found for the STUN server, print an error message and return an empty string.
        if (stunServerAddress.isEmpty) {
            // Return empty string if the STUN server can't be resolved
            print('Failed to resolve STUN server address.');
            return '';
        }

        // Select the first resolved IPv4 address as the STUN server's IP address.
        final stunServerIP = stunServerAddress.first;
        // Send the STUN request message to the STUN server using the selected IP and port.
        socket.send(stunMessage, stunServerIP, stunPort);

        // Send the STUN request message to the STUN server using the selected IP and port.
        String? publicIP;
        // Declare a variable to hold the public port returned by the STUN server.
        int? publicPort;

        // Wait for events from the socket (e.g., reading incoming data).
        await for (var event in socket) {
            // Check if the event is a "read" event, which means we have received data.
            if (event == RawSocketEvent.read) {
                // Receive the incoming datagram (network packet).
                final datagram = socket.receive();
                // If a datagram is received (i.e., not null), process its data.
                if (datagram != null) {
                    // Extract the response data from the datagram.
                    final response = datagram.data;
                    // Ensure that the response data length is greater than 20 bytes (to ensure valid data).
                    if (response.length > 20) {
                        // Extract the address family from the response (byte 25).
                        final addressFamily = response[25];
                        // Check if the address family is IPv4 (0x01 indicates IPv4).
                        if (addressFamily == 0x01) { // IPv4
                            // Extract the public port from the response (bytes 26 and 27).
                            // The port is XOR-ed with the magic cookie for additional obfuscation.
                            publicPort = (response[26] << 8 | response[27]) ^ (_magicCookie[0] << 8 | _magicCookie[1]);
                            // Parse the public IP address from bytes 28 to 31, XOR-ing with the magic cookie.
                            // This is required because the STUN protocol obfuscates the IP address using the magic cookie.
                            final ip = [
                                response[28] ^ _magicCookie[0],
                                response[29] ^ _magicCookie[1],
                                response[30] ^ _magicCookie[2],
                                response[31] ^ _magicCookie[3],
                            ].join('.');
                            // The final parsed public IP is stored in the `publicIP` variable.
                            publicIP = ip;

                        } else {
                            // If the address family is not IPv4, print a message indicating that the response is not IPv4.
                            print('Received a non-IPv4 response.');
                        }
                    }
                }
                // Break the loop after receiving the first valid response.
                break;
            }
        }
        // Close the socket after receiving the response
        socket.close();
        // Return the public IP and port
        return publicIP != null && publicPort != null ? '$publicIP:$publicPort' : '';
    }

// This function checks if the device is behind a NAT (Network Address Translation) based on its public IP address.
    Future<bool> checkIfBehindNAT(String publicIP) async {
        // Get a list of all network interfaces (e.g., Wi-Fi, Ethernet) on the device.
        List<NetworkInterface> interfaces = await NetworkInterface.list();
        // Loop through each network interface (e.g., Wi-Fi, Ethernet).
        for (var interface in interfaces) {
            // Loop through each address associated with this network interface (e.g., IP addresses).
            for (var address in interface.addresses) {
                // Check if the current address is not a private IP and matches the public IP.
                // A private IP (like 192.168.x.x, 10.x.x.x, etc.) would indicate the device is behind NAT.
                if (!isPrivateIP(address.address) && address.address == publicIP) {
                    // If the public IP matches any of the device's interface IPs, return false (device is not behind NAT).
                    return false;
                }
            }
        }
        // If no matching interface IP is found, return true (device is behind NAT).
        return true;
    }




    // Function returns the first IPv4 address found, which is the resolved address of the STUN server.
    Future stunIpAddress4(String stunServer) async {
        // Perform a DNS lookup to resolve the STUN server address for IPv4
        final stunServerAddress = (await InternetAddress.lookup(stunServer))
        .where((addr) => addr.type == InternetAddressType.IPv4)
        .toList();
        // Check if the STUN server address could not be resolved
        if (stunServerAddress.isEmpty) {
            print('Failed to resolve STUN server address.');
            // Exit the function if the server address could not be resolved
            exit;
            // return '';
        }

        //print(stunServerAddress);
        // Get the first IPv4 address (as there's usually only one)
        final stunServerIP = stunServerAddress.first;
        //  final stunServerIP4=stunServerIP.address;
        // Print out the type and the resolved STUN server IP address
        print('${stunServerIP.type} Stun Address: ${stunServerIP.address}');
        // Return the resolved STUN server IP address
        return stunServerIP;
    }

    // function returns the first IPv6 address found, which is the resolved address of the STUN server.
    Future stunIpAddress6(String stunServer) async {
        // Perform a DNS lookup to resolve the STUN server address for IPv6
        final stunServerAddress = (await InternetAddress.lookup(stunServer))
        .where((addr) => addr.type == InternetAddressType.IPv6)
        .toList();
        // Check if the STUN server address could not be resolved
        if (stunServerAddress.isEmpty) {
            print('Failed to resolve STUN server address.');
            // Exit the function if the server address could not be resolved
            exit;
            // return '';
        }
        //  print(stunServerAddress);
        // Get the first IPv6 address (as there's usually only one)
        final stunServerIP = stunServerAddress.first;
        //  InternetAddress stunServerIP6=stunServerIP.address as InternetAddress;
        // Print out the type and the resolved STUN server IP address
        print('${stunServerIP.type} Stun Address: ${stunServerIP.address}');
        // Return the resolved STUN server IP address
        return stunServerIP;
    }
*/

}
