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

    await for (var event in socket) {
      if (event == RawSocketEvent.read) {
        final datagram = socket.receive();
        if (datagram != null) {
          final response = datagram.data;
          if (response.length > 20) {
            final addressFamily = response[25];
            if (addressFamily == 0x01) { // IPv4
              final magicCookie = [0x21, 0x12, 0xA4, 0x42];
              final ip = [
                response[28] ^ magicCookie[0],
                response[29] ^ magicCookie[1],
                response[30] ^ magicCookie[2],
                response[31] ^ magicCookie[3],
              ].join('.');
              publicIP = ip;
              print('Public IP: $ip');
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
    return publicIP ?? '';
  }
}

void main() async {
  final networkInfo = NetworkInfo();
  await networkInfo.checkNAT();
}
