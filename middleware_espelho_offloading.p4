/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define PKT_INSTANCE_TYPE_NORMAL 0
#define PKT_INSTANCE_TYPE_INGRESS_CLONE 1
#define PKT_INSTANCE_TYPE_EGRESS_CLONE 2
#define PKT_INSTANCE_TYPE_COALESCED 3
#define PKT_INSTANCE_TYPE_INGRESS_RECIRC 4
#define PKT_INSTANCE_TYPE_REPLICATION 5
#define PKT_INSTANCE_TYPE_RESUBMIT 6

const bit<16> TYPE_IPV4 = 0x0800;
const bit<8> PROTO_TCP = 0x06;
const bit<8> PROTO_UDP = 0x11;

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<16> port_t;

const ip4Addr_t espelhoIP = 0xC0A83866;
const macAddr_t espelhoMAC = 0x080027e840e6;

const bit<8> CLONE_FL_1 = 1;
const bit<8> CLONE_FL_2 = 2;
const bit<8> CLONE_FL_3 = 3;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

header ethernet_t {
	macAddr_t dstAddr;
	macAddr_t srcAddr;
	bit<16>   etherType;
}

header ipv4_t {
	bit<4>    version;
	bit<4>    ihl;
	bit<8>    diffserv;
	bit<16>   totalLen;
	bit<16>   identification;
	bit<3>    flags;
	bit<13>   fragOffset;
	bit<8>    ttl;
	bit<8>    protocol;
	bit<16>   hdrChecksum;
	ip4Addr_t srcAddr;
	ip4Addr_t dstAddr;
}

header tcp_t {
	bit<16> srcPort;
	bit<16> dstPort;
	bit<32> seqNumber;
	bit<32> ackNumber;
	bit<4>  dataOffset;
	bit<3>  res;
	bit<3>  ecn;
	bit<6>  ctrl;
	bit<16> window;
	bit<16> checksum;
	bit<16> urgentPtr;
}

header tcpOptions_t {
	varbit<320> options;
}

header udp_t {
	bit<16> srcPort;
	bit<16> dstPort;
	bit<16> length;
	bit<16> checksum;
}

struct metadata {

	@field_list(CLONE_FL_1)
	ip4Addr_t stored_decapture_ip;
	@field_list(CLONE_FL_1)
	bit<16> stored_decapture_port;
	@field_list(CLONE_FL_1)
	macAddr_t stored_decapture_mac;

	@field_list(CLONE_FL_2)
	ip4Addr_t stored_decapture_ip2;
	@field_list(CLONE_FL_2)
        bit<16> stored_decapture_port2;
	@field_list(CLONE_FL_2)
        macAddr_t stored_decapture_mac2;

	@field_list(CLONE_FL_3)
	ip4Addr_t stored_decapture_ip3;
	@field_list(CLONE_FL_3)
        bit<16> stored_decapture_port3;
	@field_list(CLONE_FL_3)
        macAddr_t stored_decapture_mac3;
}

struct headers {
	ethernet_t	ethernet;
	ipv4_t		ipv4;
	tcp_t		tcp;
	tcpOptions_t	tcpOptions;
	udp_t		udp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

	bit<8> optionsLen;

	state start {
		packet.extract(hdr.ethernet);
		transition select(hdr.ethernet.etherType){
			TYPE_IPV4: parse_ipv4;
			default: accept;
		}
	}

	state parse_ipv4 {
		packet.extract(hdr.ipv4);
		transition select(hdr.ipv4.dstAddr) {
			espelhoIP: parse_transport;
			default: accept;
		}
	}

	state parse_transport {
		transition select(hdr.ipv4.protocol) {
			PROTO_TCP: parse_tcp;
			PROTO_UDP: parse_udp;
			default: accept;
		}
	}

	state parse_tcp {
		packet.extract(hdr.tcp);
        	optionsLen = 4 * (bit<8>) (hdr.tcp.dataOffset - 5);
		transition select (optionsLen) {
			0: accept;
			default: parse_tcp_options;
		}
	}

	state parse_udp {
    		packet.extract(hdr.udp);
	    	transition accept;
	}

	state parse_tcp_options {
		packet.extract(hdr.tcpOptions, (bit<32>) (optionsLen << 3));
		transition accept;
	}
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
	
	bit<1> clone_dec2 = 0x0;
	bit<1> clone_dec3 = 0x0;
	bit<1> clone_dec4 = 0x0;
	
	action drop() {
		mark_to_drop(standard_metadata);
	}

	action ipv4_forward(egressSpec_t egressPort) {
		standard_metadata.egress_spec = egressPort;
	        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
	}
    
	table ipv4_lpm {
		key = {
		    hdr.ipv4.dstAddr: lpm;
		}
		actions = {
		    ipv4_forward;
		    drop;
		    NoAction;
		}
		size = 1024;
		default_action = NoAction();
    	}


	action forwardDecapture (ip4Addr_t ip_dec1, port_t port_dec1, macAddr_t mac_dec1, ip4Addr_t ip_dec2, port_t port_dec2, macAddr_t mac_dec2, ip4Addr_t ip_dec3, port_t port_dec3, macAddr_t mac_dec3, ip4Addr_t ip_dec4, port_t port_dec4, macAddr_t mac_dec4) {
                standard_metadata.egress_spec = 2;
                hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
		if (ip_dec1 != 0 && port_dec1 != 0 && mac_dec1 != 0) {
			hdr.ethernet.dstAddr = mac_dec1;
			hdr.ethernet.srcAddr = espelhoMAC;
			hdr.ipv4.srcAddr = espelhoIP;
			hdr.ipv4.dstAddr = ip_dec1;
			hdr.udp.srcPort = hdr.udp.dstPort;
			hdr.udp.dstPort = port_dec1;
		}
		if (ip_dec2 != 0 && port_dec2 != 0 && mac_dec2 != 0) {
			clone_dec2 = 0x1;
			meta.stored_decapture_ip = ip_dec2;
			meta.stored_decapture_mac = mac_dec2;
			meta.stored_decapture_port = port_dec2;
		}
		if (ip_dec3 != 0 && port_dec3 != 0 && mac_dec3 != 0) {
			clone_dec3 = 0x1;
			meta.stored_decapture_ip2 = ip_dec3;
			meta.stored_decapture_mac2 = mac_dec3;
			meta.stored_decapture_port2 = port_dec3;
		}
		if (ip_dec4 != 0 && port_dec4 != 0 && mac_dec4 != 0) {
			clone_dec4 = 0x1;
			meta.stored_decapture_ip3 = ip_dec4;
			meta.stored_decapture_mac3 = mac_dec4;
			meta.stored_decapture_port3 = port_dec4;
		}
        }

	table espelho_udp {
		key = { hdr.ipv4.srcAddr : exact;
			hdr.udp.srcPort : exact;
			hdr.ipv4.dstAddr : exact;
			hdr.udp.dstPort : exact; }
		actions = {
			forwardDecapture;
			drop;
			NoAction;
		}
		size = 16;
		default_action = NoAction();
	}

	apply {
		if (hdr.ipv4.isValid()) {
			if (hdr.tcp.isValid()) {
				ipv4_lpm.apply();
			}
			else if (hdr.udp.isValid()) {
				if (espelho_udp.apply().hit) {
					if (clone_dec2 == 0x1) {
						clone_preserving_field_list(CloneType.I2E, 101, CLONE_FL_1);
					}
					if (clone_dec3 == 0x1) {
                                	        clone_preserving_field_list(CloneType.I2E, 102, CLONE_FL_2);
	                                }
					if (clone_dec4 == 0x1) {
                	                        clone_preserving_field_list(CloneType.I2E, 103, CLONE_FL_3);
                        	        }
				}
				else {
					ipv4_lpm.apply();
				}
			}
			else {
				ipv4_lpm.apply();
			}
		}
		else {
			ipv4_lpm.apply();
		}
	}
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

	apply {
		if (standard_metadata.instance_type == PKT_INSTANCE_TYPE_INGRESS_CLONE) {
			hdr.ipv4.srcAddr = espelhoIP;
			hdr.ipv4.dstAddr = meta.stored_decapture_ip;
			hdr.ethernet.srcAddr = espelhoMAC;
			hdr.ethernet.dstAddr = meta.stored_decapture_mac;
			hdr.udp.srcPort = hdr.udp.dstPort;
			hdr.udp.dstPort = meta.stored_decapture_port;
			standard_metadata.egress_spec = 2;
		}
	}
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
	apply {
		update_checksum(
			hdr.ipv4.isValid(),
			{ hdr.ipv4.version,
			hdr.ipv4.ihl,
			hdr.ipv4.diffserv,
			hdr.ipv4.totalLen,
			hdr.ipv4.identification,
			hdr.ipv4.flags,
			hdr.ipv4.fragOffset,
			hdr.ipv4.ttl,
			hdr.ipv4.protocol,
			hdr.ipv4.srcAddr,
			hdr.ipv4.dstAddr },
			hdr.ipv4.hdrChecksum,
			HashAlgorithm.csum16
		);
		update_checksum_with_payload(
			hdr.udp.isValid(),
			{ hdr.ipv4.srcAddr,
			hdr.ipv4.dstAddr,
			8w0,
			hdr.ipv4.protocol,
			hdr.udp.length,
			hdr.udp.srcPort,
			hdr.udp.dstPort,
			hdr.udp.length,
			16w0 
			},
			hdr.udp.checksum,
			HashAlgorithm.csum16
		);
	}
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
	apply {
		packet.emit(hdr);
	}
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;