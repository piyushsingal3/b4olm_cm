/// Define a EndpointAddress class that describes endpoint address information.
class EndpointAddress {

  /// The node id of this endpoint.
  final String? nodeID;

  /// The IPv4 of this endpoint. May not be loopback (127.0.0.0/8 or ::1), link-local (169.254.0.0/16 or fe80::/10), or link-local multicast (224.0.0.0/24 or ff02::/16).
  final String? publicipv4;

  /// The IPv6  of this endpoint. May not be loopback (127.0.0.0/8 or ::1), link-local (169.254.0.0/16 or fe80::/10), or link-local multicast (224.0.0.0/24 or ff02::/16).
  final String? publicipv6;

  /// The ipv4 port number of the endpoint.
  final int? publicipv4port;

  /// The ipv6 port number of the endpoint.
  final int? publicipv6port;

  /// The proxyipv4 of the endpoint.
  final bool? proxyipv4;

  /// The proxyipv6 of the endpoint.
  final bool? proxyipv6;

  /// The IP protocol for this port. Must be UDP, TCP. Default is TCP.
  final String? protocol;

  /// Default constructor.
  const EndpointAddress({
    required this.nodeID,
    this.publicipv4,
    this.publicipv6,
    this.publicipv4port,
    this.publicipv6port,
    this.proxyipv4,
    this.proxyipv6,
    this.protocol,
  });

// Override the toString() method to define how the object should be printed
  @override
  String toString() {
    return 'nodeid: $nodeID, pubip4: $publicipv4, pubip6 : $publicipv6, '
        'pubip4port : $publicipv4port, pubip6port : $publicipv6port, '
        'proxyipv4 : $proxyipv4, proxyipv6 : $proxyipv6, proto : $protocol ';
  }
}
// inplace of node id class we use nodeid package
/// Define the NodeID class
class NodeID {
  /// The unique identifier of the node
  final String nodeID;

  /// Public key associated with the node
  final String publicKey;

  /// Signature for verification (e.g., digital signature)
  final String sign;

  /// Default constructor.
  const NodeID({
    required this.nodeID,
    required this.publicKey,
    required this.sign,
  });

  // Override the toString() method to define how the object should be printed
  @override
  String toString() {
    return 'nodeid: $nodeID, pubkey: $publicKey';
  }
}

/// Define the Node class that combines NodeID and EndpointAddress
class Node {
  /// Node's unique identity information
  final NodeID nodeID;

  /// Node's network-related information
  final EndpointAddress endpointAddress;

  /// Constructor for Node which takes both NodeID and EndpointAddress
  const Node({
    required this.nodeID,
    required this.endpointAddress,
  });

  // Override the toString() method to define how the object should be printed
  @override
  String toString() {
    return 'nodeid: ${nodeID.toString()}, endpointadd: ${endpointAddress.toString()}';
  }
}

/// Define the Message class
class CreateMessage {
  /// A hash of the destination node id
  final String destinationNodeHash;

  /// The source node object
  final Node sourceNode;

  /// The destination node object
  final Node destinationNode;

  /// The module that is sending the message
  final String sourceModule;

  /// The module that is receiving the message
  final String destinationModule;

  /// The query or request being sent
  final String query;

  /// The layer ID of the communication
  final int layerID;

  /// The response, if any, from the destination node
  String? response;


  /// Default Constructor for the Message class
   CreateMessage({
    required this.destinationNodeHash,
    required this.sourceNode,
    required this.destinationNode,
    required this.sourceModule,
    required this.destinationModule,
    required this.query,
    required this.layerID,
    this.response,
  });
  // Override the toString() method to define how the object should be printed
  @override
  String toString() {
    return 'destnodehash: $destinationNodeHash, srcnode: $sourceNode, destnode : $destinationNode, '
        'srcmod : $sourceModule, desctmod : $destinationModule, query : $query, layerid : $layerID, resp : $response ';
  }
}
