#!/usr/bin/env python3
"""
controller.py - Reads flow stats from simple_switch_grpc via simple_switch_CLI
               (P4Runtime gRPC used only for pipeline config; register reads
                go through the Thrift CLI because BMv2 gRPC does not support them)
"""
import csv
import time
import subprocess
import p4runtime_lib.bmv2
import p4runtime_lib.helper
from p4runtime_lib.switch import ShutdownAllSwitchConnections

# ===== CONFIG =====
P4INFO_FILE  = 'traffic.p4info.txt'
BMV2_JSON    = 'traffic.json'
SWITCH_ADDR  = '127.0.0.1:50051'
DEVICE_ID    = 0
THRIFT_PORT  = 9090          # adjust if you started bmv2 with --thrift-port XXXX
MAX_FLOWS        = 4096
MAX_IAT_SAMPLES  = 10000


# ---------------------------------------------------------------------------
# Switch connection (gRPC / P4Runtime — used only for pipeline config)
# ---------------------------------------------------------------------------

def connect_to_switch():
    """Connect via P4Runtime gRPC and push the forwarding pipeline."""
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(P4INFO_FILE)
    sw = p4runtime_lib.bmv2.Bmv2SwitchConnection(
        name='traffic-sw',
        address=SWITCH_ADDR,
        device_id=DEVICE_ID,
        proto_dump_file='p4runtime_requests.txt'
    )
    sw.MasterArbitrationUpdate()
    sw.SetForwardingPipelineConfig(
        p4info=p4info_helper.p4info,
        bmv2_json_file_path=BMV2_JSON
    )
    print("✓ Connected to switch and pipeline configured")
    return sw, p4info_helper


# ---------------------------------------------------------------------------
# Register reads via simple_switch_CLI (Thrift)
# ---------------------------------------------------------------------------

def read_register_index(register_name: str, index: int,
                        thrift_port: int = THRIFT_PORT) -> int:
    """
    Read a single register slot via simple_switch_CLI.
    Output format from BMv2:  'MyIngress.flow_packet_count[42]= 17\nRuntimeCmd: '
    We find the line containing the register name, split on '=', and take
    the first whitespace token to discard the trailing 'RuntimeCmd:' prompt.
    """
    cmd = (f"echo 'register_read {register_name} {index}' | "
           f"simple_switch_CLI --thrift-port {thrift_port}")
    out = subprocess.check_output(cmd, shell=True,
                                  stderr=subprocess.DEVNULL).decode()
    for line in out.split('\n'):
        if register_name in line and '=' in line:
            return int(line.split('=')[-1].strip().split()[0])
    return 0


def read_all_flows(thrift_port: int = THRIFT_PORT) -> list:
    """
    Scan all MAX_FLOWS slots.  For each slot we first read the packet counter;
    only if it is non-zero do we pay the cost of a second CLI call for bytes.
    This mirrors the working bash approach but lives inside controller.py.
    """
    print("\tReading registers from switch (this may take a moment)...")
    flows = []

    for i in range(MAX_FLOWS):
        pkt_count = read_register_index('MyIngress.flow_packet_count', i,
                                        thrift_port)
        if pkt_count > 0:
            byte_count = read_register_index('MyIngress.flow_byte_count', i,
                                             thrift_port)
            flows.append((i, pkt_count, byte_count))

        if i % 512 == 0:
            print(f"\t  Scanned {i}/{MAX_FLOWS} flow slots...")

    return flows


# ---------------------------------------------------------------------------
# IAT samples
# ---------------------------------------------------------------------------

def read_iat_samples(thrift_port: int = THRIFT_PORT) -> list:
    """
    Read inter-arrival time samples from the switch.
    First reads iat_index[0] to find how many samples were stored,
    then reads that many entries from iat_samples[].
    Returns a list of non-zero IAT values in microseconds.
    """
    print("\tReading IAT samples from switch...")

    iat_count = read_register_index('MyIngress.iat_index', 0, thrift_port)
    print(f"\tTotal IAT samples stored: {iat_count}")

    iat_values = []
    limit = min(iat_count, MAX_IAT_SAMPLES)

    for i in range(limit):
        val = read_register_index('MyIngress.iat_samples', i, thrift_port)
        if val > 0:
            iat_values.append(val)
        if i % 1000 == 0 and i > 0:
            print(f"\t  Read {i}/{limit} samples...")

    return iat_values


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    sw, _ = connect_to_switch()

    print("\nWaiting for traffic... (will read registers after 30 seconds)")
    print("Run tcpreplay in another terminal now!")
    time.sleep(30)

    flows = read_all_flows(THRIFT_PORT)
    iat_values = read_iat_samples(THRIFT_PORT)

    # ------ Report ------
    print(f"\n{'='*60}")
    print(f"{'Flow ID':<12}{'Packets':<15}{'Bytes':<15}{'Avg Pkt Size':<15}")
    print(f"{'='*60}")

    total_packets = 0
    total_bytes   = 0

    for flow_id, pkt_count, byte_count in sorted(flows, key=lambda x: x[1],
                                                  reverse=True):
        avg_size = byte_count / pkt_count if pkt_count > 0 else 0
        print(f"{flow_id:<12}{pkt_count:<15}{byte_count:<15}{avg_size:<15.1f}")
        total_packets += pkt_count
        total_bytes   += byte_count

    print(f"{'='*60}")
    print(f"Total active flows : {len(flows)}")
    print(f"Total packets      : {total_packets}")
    print(f"Total bytes        : {total_bytes}")

    # ------ Task II Summary ------
    if flows:
        avg_sizes = [b / p for _, p, b in flows]
        print(f"\nTask II (P4) Results:")
        print(f"  Active flows      : {len(flows)}")
        print(f"  Total packets     : {total_packets}")
        print(f"  Avg packet size   : {sum(avg_sizes)/len(avg_sizes):.1f} bytes")
        print(f"  Min avg pkt size  : {min(avg_sizes):.1f} bytes")
        print(f"  Max avg pkt size  : {max(avg_sizes):.1f} bytes")

    # ------ Save CSV ------
    with open('flow_stats.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['flow_id', 'packet_count', 'byte_count', 'avg_pkt_size'])
        for flow_id, pkt_count, byte_count in flows:
            avg_size = byte_count / pkt_count if pkt_count > 0 else 0
            writer.writerow([flow_id, pkt_count, byte_count, round(avg_size, 2)])

    print("\n✓ Results saved to flow_stats.csv")

    # ------ IAT Report ------
    if iat_values:
        print(f"\n{'='*60}")
        print(f"IAT Samples Summary")
        print(f"{'='*60}")
        print(f"Non-zero samples : {len(iat_values)}")
        print(f"Avg IAT          : {sum(iat_values)/len(iat_values):.2f} us")
        print(f"Min IAT          : {min(iat_values)} us")
        print(f"Max IAT          : {max(iat_values)} us")
        print(f"{'='*60}")

        with open('iat_samples.csv', 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['iat_us'])
            for v in iat_values:
                writer.writerow([v])
        print("✓ IAT samples saved to iat_samples.csv")
    else:
        print("\n⚠ No IAT samples found.")

    ShutdownAllSwitchConnections()


if __name__ == '__main__':
    main()
