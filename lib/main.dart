import 'dart:io';
import 'dart:convert';
import 'dart:typed_data';
import 'package:http/http.dart' as http;

class NetworkInfo {
  Future<void> checkNAT() async {
    try {
      await printIps();
      String publicIP = await getPublicIP('stun.l.google.com', 19302);
      bool isBehindNAT = await checkIfBehindNAT(publicIP);
      print(isBehindNAT ? "The device is behind a   NAT." : "The device is not behind a NAT.");
    } catch (e) {
      print("Error: $e");
    }
  }

 Future<void> printIps() async {
  List<NetworkInterface> interfaces = await NetworkInterface.list(
    includeLoopback: false, 
    includeLinkLocal: false, 
  );

  print('Active Local IPs:');
  for (var interface in interfaces) {
   
    if (interface.addresses.isNotEmpty) {
      print('== Interface: ${interface.name} ==');
      for (var address in interface.addresses) {
        String ip = address.address;
        String ipType = address.type == InternetAddressType.IPv6 ? "IPv6" : "IPv4";
        bool isPrivate = isPrivateIP(ip);
        print('$ipType Address: $ip (${isPrivate ? "Private" : "Public"})');
      }
    }
  }
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

  Future<String> getPublicIP(String stunServer, int stunPort) async {
  final socket = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 0);
  print('Using local port: ${socket.port} to communicate with $stunServer:$stunPort');

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
    return '';
  }

  final stunServerIP = stunServerAddress.first;

  socket.send(stunMessage, stunServerIP, stunPort);
  print('STUN request sent to $stunServerIP:$stunPort');

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
            publicPort = (response[26] << 8 | response[27]) ^ (magicCookie[0] << 8 | magicCookie[1]);
            final ip = [
              response[28] ^ magicCookie[0],
              response[29] ^ magicCookie[1],
              response[30] ^ magicCookie[2],
              response[31] ^ magicCookie[3],
            ].join('.');
            publicIP = ip;
            print('Public IP: $ip, Port: $publicPort');
          } else {
            print('Received a non-IPv4 response.');
          }
        } else {
          print('Invalid STUN response.');
        }
        break;
      }
    }
  }

  socket.close();
  return publicIP != null && publicPort != null ? '$publicIP:$publicPort' : '';
}

bool _isValidIp(String ip) {
  final ipRegex = RegExp(
    r'^(\d{1,3}\.){3}\d{1,3}(:\d+)?$', 
  );
  return ipRegex.hasMatch(ip);
}
 final _magicCookie = [0x21, 0x12, 0xA4, 0x42];

  Future<void> determineNATType() async {
    try {
      String natType = await _performNATTests();
      print("Determined NAT Type: $natType");
    } catch (e) {
      print("Error determining NAT Type: $e");
    }
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

    // Check if the local address matches the public address (no NAT)
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
    print('STUN request sent to $stunServerIP:$stunPort');

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
              print('Mapped Address: $ip:$publicPort');
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
Future<void> startListening({int port = 8180}) async {
    final server = await ServerSocket.bind(InternetAddress.anyIPv4, port);
    print('Listening on ${server.address.address}:$port');

    await for (var socket in server) {
      print('New connection from ${socket.remoteAddress.address}:${socket.remotePort}');
      socket.write('Welcome to the listening node!\n');
      socket.listen((data) {
        print('Received: ${utf8.decode(data)}');
        socket.write('Echo: ${utf8.decode(data)}');
      });
    }
  }
  
}

void main() async {
  final networkInfo = NetworkInfo();
  await networkInfo.checkNAT();
  await networkInfo.determineNATType();
  networkInfo.startListening(port: 8180);
}
