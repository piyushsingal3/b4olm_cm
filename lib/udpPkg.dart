import 'dart:io';
import 'dart:async';
import 'package:async/async.dart';


class UDPSocket {
    final RawDatagramSocket rawSocket;
    final StreamQueue _eventQueue;

    UDPSocket(this.rawSocket) : _eventQueue = StreamQueue(rawSocket);

    static Future<UDPSocket> bindRandom(dynamic host, {
                                            bool reuseAddress = true, bool reusePort = false, int ttl = 1
                                        }) {
        return bind(host, 0, reuseAddress: reuseAddress, reusePort: reusePort, ttl: ttl);
    }

    static Future<UDPSocket> bind(dynamic host, int port, {bool reuseAddress = true, bool reusePort = false, int ttl = 1}) async {
        final socket = await RawDatagramSocket.bind(host, port, reuseAddress: reuseAddress, reusePort: reusePort, ttl: ttl);
        return UDPSocket(socket);
    }

    Future<Datagram?> receive({int? timeout, bool explode = false}) async {
        final completer = Completer<Datagram?>.sync();
        if (timeout != null) {
            Future.delayed(Duration(milliseconds: timeout)).then((_) {
                if (!completer.isCompleted) {
                    if (explode) {
                        completer.completeError('EasyUDP: Receive Timeout');
                    } else {
                        completer.complete(null);
                    }
                }
            });
        }

        Future.microtask(() async {
            try {
                while (true) {
                    final event = await _eventQueue.peek;
                    if (event == RawSocketEvent.closed) {
                        if (!completer.isCompleted) {
                            completer.complete(null);
                        }
                        break;
                    } else if (event == RawSocketEvent.read) {
                        await _eventQueue.next;
                        if (!completer.isCompleted) {
                            var datagram = rawSocket.receive();
                            completer.complete(datagram);
                        }
                        break;
                    } else {
                        await _eventQueue.next;
                    }
                }
            } catch (e) {
                print('receive fail: $e');
                if (!completer.isCompleted) {
                    completer.completeError(e);
                }
            }
        });

        return completer.future;
    }

    Future<int> send(List<int> buffer, dynamic address, int port) async {
        InternetAddress addr;
        if (address is InternetAddress) {
            addr = address;
        } else if (address is String) {
            addr = (await InternetAddress.lookup(address))[0];
        } else {
            throw 'address must be either an InternetAddress or a String';
        }
        return rawSocket.send(buffer, addr, port);
    }

    Future<void> close() async {
        try {
            rawSocket.close();
            while (await _eventQueue.peek != RawSocketEvent.closed) {
                await _eventQueue.next;
            }
            await _eventQueue.cancel();
        } catch (e) {
            print('close fail: $e');
        }
    }
}