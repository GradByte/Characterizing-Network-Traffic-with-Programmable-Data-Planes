/* traffic.p4 - Packet feature extraction for traffic characterization */

#include <core.p4>
#include <v1model.p4>

/* ===== CONSTANTS ===== */
#define MAX_FLOWS 4096
#define FLOW_HASH_WIDTH 12  // 2^12 = 4096 buckets

/* ===== HEADERS ===== */
header ethernet_t {
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16> ether_type;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<3>  flags;
    bit<13> frag_offset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdr_checksum;
    bit<32> src_addr;
    bit<32> dst_addr;
}

header tcp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4>  data_offset;
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> length;
    bit<16> checksum;
}

/* Custom header to carry computed IAT */
header custom_t {
    bit<32> iat_us;   // IAT in microseconds
    bit<32> flow_id;  // Hash-based flow ID
}

struct headers_t {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    tcp_t      tcp;
    udp_t      udp;
    custom_t   custom;
}

struct metadata_t {
    bit<32> flow_id;
    bit<32> iat_us;
}

/* ===== PARSER ===== */
parser MyParser(packet_in pkt,
                out headers_t hdr,
                inout metadata_t meta,
                inout standard_metadata_t std_meta) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            0x0800: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            6:  parse_tcp;
            17: parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition accept;
    }
}

/* ===== CHECKSUM VERIFICATION ===== */
control MyVerifyChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply { }
}

/* ===== INGRESS PROCESSING ===== */
control MyIngress(inout headers_t hdr,
                  inout metadata_t meta,
                  inout standard_metadata_t std_meta) {

    /* Register to store last packet timestamp (global IAT) */
    register<bit<32>>(1) last_timestamp_reg;
    register<bit<32>>(10000) iat_samples;
    register<bit<32>>(1)     iat_index;

    /* Registers for flow-level stats */
    register<bit<32>>(MAX_FLOWS) flow_packet_count;
    register<bit<32>>(MAX_FLOWS) flow_byte_count;
    register<bit<32>>(MAX_FLOWS) flow_last_time;

    action compute_flow_id() {
        bit<32> flow_hash;
        hash(flow_hash,
             HashAlgorithm.crc32,
             (bit<32>)0,
             { hdr.ipv4.src_addr,
               hdr.ipv4.dst_addr,
               hdr.ipv4.protocol },
             (bit<32>)MAX_FLOWS);
        meta.flow_id = flow_hash;
    }

    action compute_iat() {
        bit<32> last_time;
        bit<32> current_time;
        bit<32> idx;
        current_time = (bit<32>)std_meta.ingress_global_timestamp;
        last_timestamp_reg.read(last_time, 0);
        meta.iat_us = current_time - last_time;
        last_timestamp_reg.write(0, current_time);

        // Store IAT sample
        iat_index.read(idx, 0);
        iat_samples.write(idx, meta.iat_us);
        iat_index.write(0, idx + 1);
     }

    action update_flow_stats() {
        bit<32> pkt_count;
        bit<32> byte_count;
        flow_packet_count.read(pkt_count, meta.flow_id);
        flow_byte_count.read(byte_count, meta.flow_id);
        pkt_count = pkt_count + 1;
        byte_count = byte_count + (bit<32>)std_meta.packet_length;
        flow_packet_count.write(meta.flow_id, pkt_count);
        flow_byte_count.write(meta.flow_id, byte_count);
    }

    action add_custom_header() {
        hdr.custom.setValid();
        hdr.custom.iat_us  = meta.iat_us;
        hdr.custom.flow_id = meta.flow_id;
    }

    action drop() {
        mark_to_drop(std_meta);
    }

    table ipv4_forward {
        key = {
            hdr.ipv4.dst_addr: lpm;
        }
        actions = {
            drop;
            NoAction;
        }
        default_action = NoAction();
    }

    apply {
        if (hdr.ipv4.isValid()) {
            compute_flow_id();
            compute_iat();
            update_flow_stats();
            add_custom_header();
            ipv4_forward.apply();
        }
    }
}

/* ===== EGRESS PROCESSING ===== */
control MyEgress(inout headers_t hdr,
                 inout metadata_t meta,
                 inout standard_metadata_t std_meta) {
    apply { }
}

/* ===== CHECKSUM COMPUTATION ===== */
control MyComputeChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply { }
}

/* ===== DEPARSER ===== */
control MyDeparser(packet_out pkt, in headers_t hdr) {
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.udp);
        pkt.emit(hdr.custom);
    }
}

/* ===== SWITCH INSTANTIATION ===== */
V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
