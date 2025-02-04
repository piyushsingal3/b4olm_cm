import 'dart:io';
import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';


class NetworkInfo {
static Future<Map<String, int>> loadServersFromJson(String filePath) async {
  try {
    print('Looking for JSON file at: ${Directory.current.path}/${filePath}');

    final file = File(filePath);
    if (!await file.exists()) {
      print('Error: JSON file not found.');
      return {};
    }

    String content = await file.readAsString();
    Map<String, dynamic> jsonData = jsonDecode(content);

    Map<String, int> servers = {};
    if (jsonData['servers'] != null && jsonData['servers'] is List) {
      for (var server in jsonData['servers']) {
        if (server is Map<String, dynamic> && 
            server['publicIpv4'] is String && 
            server['listeningPort'] is int) {
          
          String ip = server['publicIpv4'].trim();
          int port = server['listeningPort'];
          servers[ip] = port;
        }
      }
    }
    return servers;
  } catch (e) {
    print('Error reading JSON file: \$e');
    return {};
  }
}

static Future<String> findClosestServer(Map<String, int> servers) async {
  String closestServer = '';
  int minTime = 99999999;

  for (var entry in servers.entries) {
    String server = entry.key;
    int port = entry.value;

    try {
      Stopwatch stopwatch = Stopwatch()..start();
      Socket socket = await Socket.connect(server, port, timeout: Duration(seconds: 3));
      stopwatch.stop();
      socket.destroy();  // Close connection

      int elapsedTime = stopwatch.elapsedMilliseconds;
      print('Server ${server} on port ${port} responded in ${elapsedTime} ms');

      if (elapsedTime < minTime) {
        minTime = elapsedTime;
        closestServer = '${server}:${port}';
      }
    } catch (e) {
      print('Failed to connect to ${server} on port ${port}: ${e}');
    }
  }

  return closestServer;
}

  Future<void> checkNAT() async {
    try {
      await printIps();
      Map< String , dynamic> publicIPv4=await getPublicIPv4('stun.l.google.com', 19302);
      Map< String , dynamic> publicIPv6=await getPublicIPv6('stun.l.google.com', 19302);
      String publicIpv4=publicIPv4['publicIP'];
      String publicIpv6=publicIPv6['publicIP'];
      bool isBehindNAT = await checkIfBehindNAT(publicIpv4);
    } catch (e) {
      print("Error: $e");
    }
  }


  Future<List<List<dynamic>>> printIps() async {
    List<List<dynamic>> activeIPs = [];
    try {
      ProcessResult result = await Process.run(
        'powershell',
        [
          '-Command',
          r'(Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -ne $null }).InterfaceAlias'
        ],
      );

      if (result.exitCode == 0) {
  
        String output = result.stdout.trim();
        if (output.isNotEmpty) {
          String activeInterfaceName = output;



          for (var interface in await NetworkInterface.list()) {
            if (interface.name == activeInterfaceName) {
              for (var address in interface.addresses) {
                String ip = address.address;
                String ipType =
                    address.type == InternetAddressType.IPv6 ? "IPv6" : "IPv4";
                String isPrivate = isPrivateIP(ip) ? "Yes" : "No";
               
                Map< String , dynamic> publicIPv4=await getPublicIPv4('stun.l.google.com', 19302);
                Map< String , dynamic> publicIPv6=await getPublicIPv6('stun.l.google.com', 19302);
                String? public4=publicIPv4['publicIP'];
                String? public6=publicIPv6['publicIP'];
                int? publicPort=publicIPv4['publicPort'];
                bool? behindNAT = public4 != null ? await checkIfBehindNAT(public4) : null;
                String? natType = public6 != null && behindNAT != null
                    ? await determineNATType()
                    : "";
                int? isBehindNAT=0;
                if(behindNAT==true){
                    isBehindNAT=1;
                }

                // [type, address, private, publicIP,publicPort ,isBehindNAT, natType]
                activeIPs.add([ipType, ip, isPrivate, public4,publicPort, isBehindNAT, natType,public6]);


              }
              break;
            }
          }
        } else {
          print('No active interface found.');
        }
      } else {
        print('Failed to determine the active interface.');
      }
    } catch (e) {
      print('Error: $e');
    }
    return activeIPs;
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

  Future<void> startListening({int port = 8888}) async {
    try {
      final server = await ServerSocket.bind(InternetAddress.anyIPv4, port);
      print('Server is listening on all interfaces (0.0.0.0):$port');

      await for (var socket in server) {
        print('New connection from ${socket.remoteAddress.address}:${socket.remotePort}');
        
        socket.listen(
          (data) {
            print('Received: ${utf8.decode(data)}');
            socket.write('HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nWelcome to the server!');
          },
          onDone: () {
            print('Client closed the connection');
            socket.close();  
          },
          onError: (error) {
            print('Error: $error');
            socket.close();
          }
        );
      }
    } catch (e) {
      print('Error starting the server: $e');
    }
  }
}

void main() async {
  final networkInfo = NetworkInfo();
  await networkInfo.checkNAT();
  await networkInfo.determineNATType();
  
  List<List<dynamic>> activeIPs = await networkInfo.printIps();
  

  if (activeIPs.isEmpty) {
    print('No active IPs found.');
  } else {
    print('All IPs of active interface:');
    for (var ipInfo in activeIPs) {
      print('Type: ${ipInfo[0]}, Address: ${ipInfo[1]}, Private: ${ipInfo[2]}');
      print('Public IP: ${ipInfo[3]},Public Port: ${ipInfo[4]} NATed: ${ipInfo[5]}, NAT Type: ${ipInfo[6]}, Public IPv6:${ipInfo[7]}');
    }
  }
 
    Map<String, int> servers = await NetworkInfo.loadServersFromJson('servers.json');
  if (servers.isEmpty) {
    print('No servers found in JSON file.');
    return;
  }

  String closestServer = await NetworkInfo.findClosestServer(servers);
  print('Closest server: $closestServer');
  await networkInfo.startListening(port: 8888);

}
