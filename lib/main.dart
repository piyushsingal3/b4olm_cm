import 'dart:collection';
import 'dart:io';
import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';
import 'udpPkg.dart';
import 'networkInformation.dart';

class NetworkInfo {



Map<String, Socket> connectedClients = {};
Queue<String> messageQueue = Queue<String>();
Map<String, Queue<String>> cmOutBuffer = {};
Map<String, Queue<String>> rootNodeBuffer = {};
Socket? relaySocket;





void _removeClient(Socket socket) {
  String? keyToRemove;

  connectedClients.forEach((key, value) {
    if (value == socket) {
      keyToRemove = key;
    }
  });

  if (keyToRemove != null) {
    connectedClients.remove(keyToRemove);
    print("Client $keyToRemove disconnected.");
  }
}


Future<void> startRelayServer({int port = 8888}) async {
  try {
    final server = await ServerSocket.bind(InternetAddress.anyIPv4, port);
    print('Relay Server is listening on port $port');

    await for (var socket in server) {
      socket.listen(
        (data) {
          String message = utf8.decode(data);
          print('Received: $message');

          try {
            Map<String, dynamic> receivedData = jsonDecode(message);

            if (receivedData.containsKey("command") && receivedData["command"] == "REGISTER") {
              // Handles relay registration
              String nodeId = receivedData["node"]["hashID"];
              connectedClients[nodeId] = socket;
              print(socket);
              print('Remote Address: ${socket.remoteAddress.address}');
              print('Remote Port: ${socket.remotePort}');
              print('Local Address: ${socket.address.address}');
              print('Local Port: ${socket.port}');
              print("Node registered: $nodeId  socket:  " );

              _sendBufferedMessages(nodeId);
            } 
            else if (receivedData.containsKey("destinationNode")) {
              // Handle relaying messages
              String targetId = receivedData["destinationNodeHash"];
              String relayMessage = receivedData["query"];
              String response = receivedData["response"];
              Map<String, dynamic> sourceNode=receivedData["sourceNode"];
              Map<String, dynamic> destinationNode=receivedData["destinationNode"];

              _relayMessage(sourceNode,destinationNode,targetId, relayMessage,response);
            }
          } catch (e) {
            print("Error decoding message: $e");
          }
        },
        onDone: () {
          _removeClient(socket);
        },
        onError: (error) {
          print('Error: $error');
          _removeClient(socket);
        },
      );
    }
  } catch (e) {
    print('Error starting relay server: $e');
  }
}

// Function to relay messages
Future<void> _relayMessage(Map<String, dynamic> sourceNode, Map<String, dynamic> destinationNode, String targetId, String query,String response) async {
  try {
    Map<String, dynamic> CreateMessage = {
      "destinationNodeHash": targetId,
      "sourceNode": sourceNode,
      "destinationNode": destinationNode,
      "sourceModule": "CM",
      "destinationModule": "CM",
      "query": query,
      "layerID": 0,
      "response": response
    };

    String filePath = 'rttable0.json';
    List<Map<String, dynamic>> nodes = await NetworkInfo.readJsonFile(filePath);

    for (var node in nodes) {
      printNode(node);
      print(calculateDistance(node['hashID'], targetId));
    }

    if (targetId == nodes[0]['hashID']) {
      print("Message received by the target node: $targetId");
  
    } else if (connectedClients.containsKey(targetId)) {
      try {
        connectedClients[targetId]!.write(jsonEncode(CreateMessage));
        print("Relayed message to Node $targetId - $query");
     
      } catch (e) {
        cmOutBuffer.putIfAbsent(targetId, () => Queue<String>()).add(jsonEncode(CreateMessage));
        print("Failed to send message to $targetId directly, keeping in buffer.");
      }
    } else {
      print("Target Node $targetId is not connected. Trying to send via closest node.");

      Map<String, dynamic>? minDistNode;
      BigInt minDist = BigInt.parse('1' + '0' * 1000);

      for (var node in nodes) {
        BigInt currentDist = calculateDistance(node['hashID'], targetId);
        if (currentDist < minDist) {
          minDist = currentDist;
          minDistNode = node;
        }
      }

      if (minDistNode != null) {
        await _sendViaProxy(minDistNode, CreateMessage, targetId);
      }
    }
  } catch (e) {
    print('Relay server failed to send message to Node $targetId - $e');
  }
}

Future<void> _sendViaProxy(Map<String, dynamic> proxyNode, Map<String, dynamic> message, String targetId) async {
  try {
    Socket proxySocket = await Socket.connect(proxyNode['publicIpv4'], proxyNode['listeningPort']);
    proxySocket.write(jsonEncode(message));
    print('Relayed message to next proxy: ${proxyNode['hashID']}');
  } catch (e) {
    rootNodeBuffer.putIfAbsent(targetId, () => Queue<String>()).add(jsonEncode(message));
    print("Couldn't send message to closest proxy: ${proxyNode['hashID']}. Keeping in buffer.");
  }
}


void _sendBufferedMessages(String nodeId) {
  if (cmOutBuffer.containsKey(nodeId)) {
    while (cmOutBuffer[nodeId]!.isNotEmpty) {
      String message = cmOutBuffer[nodeId]!.removeFirst();
      connectedClients[nodeId]!.write(message);
      print("Sent buffered message to Node $nodeId - $message");
    }
    cmOutBuffer.remove(nodeId); // Remove entry if queue is empty
  }
}


// Function to register and maintain a connection


Future<void> registerWithRelay(String relayIp, int relayPort, Map<String, dynamic> myNode) async {
  try {
    relaySocket = await Socket.connect(relayIp, relayPort);
    print('Registered with relay: $relayIp:$relayPort');

    // Send registration message
    Map<String, dynamic> registrationMessage = {"command": "REGISTER", "node": myNode};
    relaySocket!.write(jsonEncode(registrationMessage));

    relaySocket!.listen(
      (data) {
        String received = utf8.decode(data);
        print('Received from relay: $received');

        try {
          Map<String, dynamic> receivedMessage = jsonDecode(received);

          if (receivedMessage.containsKey("destinationNodeHash") &&
              receivedMessage.containsKey("sourceNode") &&
              receivedMessage.containsKey("destinationNode")) {
           
            // Check if "response" field is absent or empty
             print(receivedMessage["response"].toString().isEmpty);
            if (!receivedMessage.containsKey("response") || receivedMessage["response"].toString().isEmpty) {
              Map<String, dynamic> responseMessage = {
                "destinationNodeHash": receivedMessage["sourceNode"]["hashID"],
                "sourceNode": receivedMessage["destinationNode"],
                "destinationNode": receivedMessage["sourceNode"],
                "sourceModule": receivedMessage["destinationModule"],
                "destinationModule": receivedMessage["sourceModule"],
                "query": receivedMessage["query"],
                "layerID": receivedMessage["layerID"],
                "response": "Received by Node ${myNode['hashID']}"
              };

              relaySocket!.write(jsonEncode(responseMessage));
              print("Replied to relay: ${jsonEncode(responseMessage)}");
            }
          }

        } catch (e) {
          print("Error decoding received message: $e");
        }
      },
      onDone: () {
        print('Disconnected from relay.');
        relaySocket = null;
      },
      onError: (error) {
        print('Relay socket error: $error');
        relaySocket = null;
      },
    );

    // Check and send any buffered messages for this node
    String nodeId = myNode["hashID"];
    if (cmOutBuffer.containsKey(nodeId)) {
      while (cmOutBuffer[nodeId]!.isNotEmpty) {
        String queuedMessage = cmOutBuffer[nodeId]!.removeFirst();
        relaySocket!.write(queuedMessage);
        print("Sent queued message to relay: $queuedMessage");
      }
      cmOutBuffer.remove(nodeId); // Clear buffer after sending
    }

  } catch (e) {
    print('Failed to register with relay: $e');

    // Store message in buffer for retry
    String nodeId = myNode["hashID"];
    cmOutBuffer.putIfAbsent(nodeId, () => Queue<String>()).add(jsonEncode({"command": "REGISTER", "node": myNode}));
    print("Stored registration message in buffer for retry.");
  }
}


// Function to send a message via relay using the same connection
Future<void> sendMessageViaRelay(Map<String, dynamic> sourceNode, Map<String, dynamic> destinationNode, String message) async {
  try {
    Map<String, dynamic> CreateMessage = {
      "destinationNodeHash": destinationNode["hashID"],
      "sourceNode": sourceNode,
      "destinationNode": destinationNode,
      "sourceModule":"CM",
      "destinationModule":"CM",
      "query": message,
      "layerID":0,
      "response":""
    };

    if (relaySocket != null) {
      relaySocket!.write(jsonEncode(CreateMessage));
      print('Message sent via relay.');
    } else {
      messageQueue.add(jsonEncode(CreateMessage));
      print('Message queued because relay connection is not established.');
    }
  } catch (e) {
    print('Failed to send message via relay: $e');
  }
}




  Future<void> checkNAT() async {
    try {
      
      Map< String , dynamic> publicIPv4=await getPublicIPv4('stun.l.google.com', 19302);
      Map< String , dynamic> publicIPv6=await getPublicIPv6('stun.l.google.com', 19302);
      String publicIpv4=publicIPv4['publicIP'];
      String publicIpv6=publicIPv6['publicIP'];
      bool isBehindNAT = await checkIfBehindNAT(publicIpv4);
    } catch (e) {
      print("Error: $e");
    }
  }


 Future<List<List<dynamic>>> getNetworkInfo(String stunServer, int stunPort) async {
      List<List<dynamic>> activeIPs = [];
      try {
             
              var networkInterface=await NetworkInterface.list(includeLinkLocal: false,includeLoopback: false);
              List<dynamic> actIPList=await getActiveIPList(networkInterface);
              
                for(var address in actIPList){
          
                  
                  String ip = address.address;
                  String ipType = address.type == InternetAddressType.IPv6 ? "IPv6" : "IPv4";
                  String isPrivate = isPrivateIP(ip) ? "Yes" : "No";
                  bool? behindNAT;
                  int? publicPort;
                  String? natType, publicIP;

                  if((isPrivate.startsWith("Y"))){
                    if(ipType == "IPv4"){
                      Map< String , dynamic> public=await getPublicIPv4(stunServer, stunPort);
                      publicIP=public['publicIP'];
                      publicPort=public['publicPort'];
                    }
                    else if(ipType == "IPv6"){
                      Map< String , dynamic> public=await getPublicIPv6(stunServer, stunPort);
                      publicIP=public['publicIP'];
                      publicPort=public['publicPort'];
                    }
                    behindNAT = publicIP != null ? await checkIfBehindNAT(publicIP) : null;
                    natType = publicIP != null && behindNAT != null
                        ? await determineNATType()
                        : null;

                  }

                  if((isPrivate.startsWith("N"))){
                    publicIP=ip;
                    if(ipType == "IPv4") {
                      publicPort =
                          (await UDPSocket.bind(InternetAddress.anyIPv4, 0))
                              .rawSocket.port;
                    }else if(ipType == "IPv6"){
                      publicPort =
                          (await UDPSocket.bind(InternetAddress.anyIPv6, 0))
                              .rawSocket.port;
                    }
                    natType=null;
                  }

                  int? isBehindNAT=0;
                  if(behindNAT==true){
                    isBehindNAT=1;
                  }

                  // [type, address, private, publicIP,publicPort isBehindNAT, natType]
                  activeIPs.add([ipType, ip, isPrivate, publicIP,publicPort, isBehindNAT, natType]);

                }
          
      } catch (e) {
        print('Error: $e');
      }
      return activeIPs;
    }

  Future<List<InternetAddress>> getActiveIPList(List<NetworkInterface> interfaces) async {
  List<InternetAddress> internetIPs = [];

  for (var interface in interfaces) {
    
    
    for (var addr in interface.addresses) {
   
      
      try {
       
        Socket socket = await Socket.connect(
          '8.8.8.8',
          53,
          sourceAddress: addr.address,
          timeout: Duration(seconds: 2),
        );
        
        socket.destroy();
        //print("Connected successfully: ${addr.address}");
        internetIPs.add(addr);  

      } catch (e) {
        //print(" Failed to connect: ${addr.address}, Error: $e");
      }
    }
   
  }
   return internetIPs;
  
}

  Future<bool> checkIfBehindNAT(String publicIP) async {
    List<NetworkInterface> interfaces = await NetworkInterface.list();

    for (var interface in interfaces) {
      for (var address in interface.addresses) {
        String localIP = address.address;
        if (!isPrivateIP(localIP) && localIP == publicIP) {
          return false; 
        }
      }
    }

    return true;
  }

  bool isPrivateIP(String ip) {
    final parts = ip.split('.');
    if (parts.length != 4) return false;

    final first = int.tryParse(parts[0]) ?? -1;
    final second = int.tryParse(parts[1]) ?? -1;

    if (first == 10) return true; // 10.0.0.0 - 10.255.255.255
    if (first == 172 && second >= 16 && second <= 31) return true; // 172.16.0.0 - 172.31.255.255
    if (first == 192 && second == 168) return true; // 192.168.0.0 - 192.168.255.255
    if (ip == "127.0.0.1") return true; 
    return false; 
  }

Future<Map<String, dynamic>> getPublicIPv4(String stunServer, int stunPort) async {
  final socket = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 0);

  final transactionId = List<int>.generate(12, (i) => i);
  final stunMessage = Uint8List.fromList([
    0x00, 0x01,
    0x00, 0x00,
    0x21, 0x12, 0xA4, 0x42,
    ...transactionId,
  ]);

  final stunServerAddress = (await InternetAddress.lookup(stunServer))
      .where((addr) => addr.type == InternetAddressType.IPv4)
      .toList();

  if (stunServerAddress.isEmpty) {
    print('Failed to resolve STUN server address.');
    return {'publicIP': null, 'publicPort': null};
  }

  final stunServerIP = stunServerAddress.first;

  socket.send(stunMessage, stunServerIP, stunPort);

  String? publicIP;
  int? publicPort;

  await for (var event in socket) {
    if (event == RawSocketEvent.read) {
      final datagram = socket.receive();
      if (datagram != null) {
        final response = datagram.data;
        if (response.length > 20) {
          final addressFamily = response[25];
          if (addressFamily == 0x01) { // IPv4
            final magicCookie = [0x21, 0x12, 0xA4, 0x42];
            publicPort = (response[26] << 8 | response[27]) ^
                (magicCookie[0] << 8 | magicCookie[1]);
            final ip = [
              response[28] ^ magicCookie[0],
              response[29] ^ magicCookie[1],
              response[30] ^ magicCookie[2],
              response[31] ^ magicCookie[3],
            ].join('.');
            publicIP = ip;

          } else {
            print('Received a non-IPv4 response.');
          }
        } else {
          print('Invalid STUN response.');
        }
      }
      break;
    }
  }

  socket.close();
  return {
    'publicIP': publicIP,
    'publicPort': publicPort,
  };
}
Future<Map<String, dynamic>> getPublicIPv6(String stunServer, int stunPort) async {
  final socket = await RawDatagramSocket.bind(InternetAddress.anyIPv6, 0);

  final transactionId = List<int>.generate(12, (i) => i);
  final stunMessage = Uint8List.fromList([
    0x00, 0x01,
    0x00, 0x00,
    0x21, 0x12, 0xA4, 0x42,
    ...transactionId,
  ]);

  final stunServerAddress = (await InternetAddress.lookup(stunServer))
      .where((addr) => addr.type == InternetAddressType.IPv6)
      .toList();

  if (stunServerAddress.isEmpty) {
    
    return {'publicIP': "", 'publicPort': null};
  }

  final stunServerIP = stunServerAddress.first;

  socket.send(stunMessage, stunServerIP, stunPort);

  String? publicIP;
  int? publicPort;

  await for (var event in socket) {
    if (event == RawSocketEvent.read) {
      final datagram = socket.receive();
      if (datagram != null) {
        final response = datagram.data;
        if (response.length > 20) {
          final addressFamily = response[25];
          if (addressFamily == 0x02) { // IPv6
  publicPort = (response[26] << 8 | response[27]) ^
      (transactionId[0] << 8 | transactionId[1]);

  final ip = List.generate(16, (i) => 
    (response[28 + i] ^ transactionId[i % transactionId.length])
    .toRadixString(16).padLeft(2, '0'))
    .join(':');
  publicIP = ip.replaceAllMapped(
    RegExp(r'(:0{1,3})+'), 
    (match) => ':'
  );
} else {
            print('Received a non-IPv6 response.');
          }
        } else {
          print('Invalid STUN response.');
        }
      }
      break;
    }
  }

  socket.close();
  return {'publicIP': publicIP, 'publicPort': publicPort};
}
 Future<String> determineNATType() async {
    try {
      String natType = await _performNATTests();
      return natType;
    } catch (e) {
      print("Error determining NAT Type: $e");
    }
    return "Null";
  }

  Future<String> _performNATTests() async {
    String stunServer = 'stun.l.google.com';
    int stunPort = 19302;

    // Test I: Send request without changing IP or port
    String mappedAddressTest1 = await _stunTest(stunServer, stunPort, changeIP: false, changePort: false);
    if (mappedAddressTest1.isEmpty) {
      return "No UDP connectivity";
    }

    // Parse the mapped address from Test I
    var parts = mappedAddressTest1.split(':');
    if (parts.length != 2) return "Invalid response in Test I";
    String publicIP1 = parts[0];
    int publicPort1 = int.parse(parts[1]);

  
    List<NetworkInterface> interfaces = await NetworkInterface.list();
    bool isNatted = true;

    for (var interface in interfaces) {
      for (var address in interface.addresses) {
        if (address.address == publicIP1) {
          isNatted = false;
          break;
        }
      }
    }

    if (!isNatted) {
      return "No NAT";
    }

    // Test II: Changing both IP and port
    String test2Response = await _stunTest(stunServer, stunPort, changeIP: true, changePort: true);
    if (test2Response.isNotEmpty) {
      return "Full Cone NAT";
    }

    // Test III: Changing only the port
    String test3Response = await _stunTest(stunServer, stunPort, changeIP: false, changePort: true);
    if (test3Response.isNotEmpty) {
      return "Restricted Cone NAT";
    }

    // Re-running Test I to check for Symmetric NAT
    String mappedAddressTest1Again = await _stunTest(stunServer, stunPort, changeIP: false, changePort: false);
    if (mappedAddressTest1Again != mappedAddressTest1) {
      return "Symmetric NAT";
    }

    return "Port Restricted Cone NAT";
  }
   final _magicCookie = [0x21, 0x12, 0xA4, 0x42];

  Future<String> _stunTest(String stunServer, int stunPort, {bool changeIP = false, bool changePort = false}) async {
    final socket = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 0);

    final transactionId = List<int>.generate(12, (i) => i);
    final stunMessage = Uint8List.fromList([
      0x00, 0x01,
      0x00, 0x08,
      ..._magicCookie,
      ...transactionId,
      0x00, 0x03, 
      0x00, 0x04,
      0x00, 0x00, 0x00, (changeIP ? 0x04 : 0x00) | (changePort ? 0x02 : 0x00),
    ]);

    final stunServerAddress = (await InternetAddress.lookup(stunServer))
        .where((addr) => addr.type == InternetAddressType.IPv4)
        .toList();

    if (stunServerAddress.isEmpty) {
      print('Failed to resolve STUN server address.');
      return '';
    }

    final stunServerIP = stunServerAddress.first;
    socket.send(stunMessage, stunServerIP, stunPort);


    String? publicIP;
    int? publicPort;

    await for (var event in socket) {
      if (event == RawSocketEvent.read) {
        final datagram = socket.receive();
        if (datagram != null) {
          final response = datagram.data;
          if (response.length > 20) {
            final addressFamily = response[25];
            if (addressFamily == 0x01) { // IPv4
              publicPort = (response[26] << 8 | response[27]) ^ (_magicCookie[0] << 8 | _magicCookie[1]);
              final ip = [
                response[28] ^ _magicCookie[0],
                response[29] ^ _magicCookie[1],
                response[30] ^ _magicCookie[2],
                response[31] ^ _magicCookie[3],
              ].join('.');
              publicIP = ip;

            } else {
              print('Received a non-IPv4 response.');
            }
          }
        }
        break;
      }
    }

    socket.close();
    return publicIP != null && publicPort != null ? '$publicIP:$publicPort' : '';
  }

 
static Future<List<Map<String, dynamic>>> readJsonFile(String filePath) async {
  try {
    final file = File(filePath);

    if (!await file.exists()) {
      print("Error: File does not exist.");
      return [];
    }

    String jsonString = await file.readAsString();

    if (jsonString.trim().isEmpty) {
      print("Error: JSON file is empty.");
      return [];
    }

    List<dynamic> jsonData = jsonDecode(jsonString);

    if (jsonData is! List) {
      print("Error: JSON structure is invalid. Expected a list.");
      return [];
    }

    return List<Map<String, dynamic>>.from(jsonData);
  } catch (e) {
    print("Error reading JSON file: $e");
    return [];
  }
}
BigInt calculateDistance(String nodeId, String proxyNodeId) {
  // Convert hex node IDs to BigInt for comparison
  BigInt nodeBigInt = BigInt.parse(nodeId, radix: 16);
  BigInt proxyBigInt = BigInt.parse(proxyNodeId, radix: 16);

  // Perform XOR operation and return BigInt distance
  return nodeBigInt ^ proxyBigInt;
}

}

void main() async {
  final networkInfo = NetworkInfo();
  final networkDetails=NetworkDetails();
  await networkInfo.checkNAT();
  await networkInfo.determineNATType();
  String stunServer='stun.l.google.com';
  int stunPort=19302;
  List<List<dynamic>> activeIPs = await networkDetails.getNetworkInfo(stunServer,stunPort);
  String filePath = 'lib/rttable0.json'; 

  List<Map<String, dynamic>> nodes = await NetworkInfo.readJsonFile(filePath);
  

   if (activeIPs.isEmpty) {
    print('No active  Network IPs found i.e. no internet.');
   } else {
    print('All IPs of active interface:');
    for (var ipInfo in activeIPs) {
      print('Type: ${ipInfo[0]}, Address: ${ipInfo[1]}, Private: ${ipInfo[2]},Public IP: ${ipInfo[3]},Public Port: ${ipInfo[4]} ');
      
    }
   }
   if (nodes.isEmpty) {
    print("No nodes found in JSON file.");
    return;
  }
  for (var node in nodes) {
    printNode(node);
  }


  print(NetworkInfo().calculateDistance(nodes[5]['hashID'],nodes[4]['hashID']));

  Map<String, int> servers = {
    for (var node in nodes)
      if (node['publicIpv4'] is String && node['listeningPort'] is int)
        node['publicIpv4'].trim(): node['listeningPort']
    };

  if (servers.isEmpty) {
    print('No servers found in JSON file.');
    return;
  }

    Map<String, dynamic>? minDistNode;
    BigInt minDist = BigInt.parse('1' + '0' * 1000);
    
    String proxyfilePath = 'lib/proxy.json'; 
    List<Map<String, dynamic>> proxynodes = await NetworkInfo.readJsonFile(proxyfilePath);
    for (var node in proxynodes) {
      printProxy(node);
    }
    for (var node in proxynodes) {
        BigInt currentDist = NetworkInfo().calculateDistance(nodes[0]['hashID'], node['hashID']);
        if (currentDist < minDist) {
          minDist = currentDist;
          minDistNode = node;
        }
    }
    
    if (minDistNode != null) {
        print("Connecting with minimum distance proxy : ${minDistNode['publicIpv4']}");
        try{
          await networkInfo.registerWithRelay(minDistNode['publicIpv4'],minDistNode['listeningPort'],nodes[0]);
        }
        catch(e) {
            print("Not Registered! Minimum Distance node is not active ${e}");
        }
    }
    else{
      print("No Proxy node found");
    }


  await networkInfo.sendMessageViaRelay(nodes[0],nodes[0],"Hello remote node" );



}

void printNode(Map<String, dynamic> node) {
  print("Node Details:");
  print("  Hash ID: ${node['hashID']}");
  print("  Public IPv4: ${node['publicIpv4']}");
  print("  Listening Port: ${node['listeningPort']}");
  print("  NAT Status: ${node['natStatus']}");
  print("  ----------------------");
}

void printProxy(Map<String, dynamic> node) {
  print(" Proxy Node Details:");
  print("  Hash ID: ${node['hashID']}");
  print("  Public IPv4: ${node['publicIpv4']}");
  print("  Listening Port: ${node['listeningPort']}");
  print("  NAT Status: ${node['natStatus']}");
  print("  ----------------------");
}
