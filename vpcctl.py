#!/usr/bin/env python3
import argparse
import subprocess
import sys
import ipaddress
import json
import os
STATE_FILE = "./vpc_state.json"


# =============================================================================
# Helper Functions
# =============================================================================
def run(cmd, ignore_error=False):
    print(f"+ {cmd}")
    try:
        result = subprocess.run(
            cmd, shell=True, check=True, capture_output=True, text=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        if ignore_error:
            print(f"Warning: Ignored: {e.stderr.strip()}")
            return None
        print(f"Error: {e}")
        print(f"   stderr: {e.stderr.strip()}")
        sys.exit(1)

def get_default_iface():
    out = subprocess.getoutput("ip route | awk '/default/ {print $5; exit}'")
    return out.strip() or "eth0"

def load_state():
    """Load VPCS state from JSON file if it exists."""
    global VPCS
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r") as f:
                VPCS.update(json.load(f))
            print(f"Loaded existing state from {STATE_FILE}")
        except Exception as e:
            print(f"Warning: Could not load state file: {e}")
    else:
        print("No existing state found. Starting fresh.")

def save_state():
    """Save current VPCS state to JSON file."""
    try:
        with open(STATE_FILE, "w") as f:
            json.dump(VPCS, f, indent=2)
        print(f"State saved to {STATE_FILE}")
    except Exception as e:
        print(f"Error saving state: {e}")


VPCS = {}  
# =============================================================================
# VPC Management
# =============================================================================

def create_vpc(name, cidr):
    if name in VPCS:
        print(f"VPC '{name}' already exists. Skipping.")
        return

    bridge_name = f"br-{name}"

    try:
        vpc_net = ipaddress.ip_network(cidr, strict=False)
    except Exception as e:
        print(f"Invalid CIDR: {e}")
        sys.exit(1)
        
    # === Clean up bridge if exists ===
    check__bridge_exist_result = subprocess.run(
        f"ip link show {bridge_name}", shell=True, capture_output=True, text=True
    )
    if check__bridge_exist_result.returncode == 0:
        print(f"   Bridge {bridge_name} exists. Deleting...")
        run(f"ip link set {bridge_name} down", ignore_error=True)
        run(f"ip link del {bridge_name}", ignore_error=True)


    # Create bridge
    print(f"Creating bridge {bridge_name}")
    run(f"ip link add name {bridge_name} type bridge")
    run(f"ip link set {bridge_name} up")
    run (f"ip addr add {cidr} dev { bridge_name}")
    print(f"   ✅ {name} bridge created.")

    run(f"sudo iptables -A FORWARD -i {bridge_name} -j ACCEPT")
    run(f"sudo iptables -A FORWARD -o {bridge_name} -j ACCEPT")


    VPCS[name] = { 
        "bridge": bridge_name,
        "cidr": cidr,
        "subnets": {},
        "peers": [],
        "firewall_policies": {}
    }
    print(f"VPC '{name}' created (CIDR: {cidr})")
    save_state()

def add_subnet(vpc_name, subnet_name, subnet_cidr, stype="private"):
    print(VPCS)
    run(f"")

    if vpc_name not in VPCS:
        print(f"VPC '{vpc_name}' doesnt exist")
        sys.exit(1)

    vpc = VPCS[vpc_name]
    if subnet_name in vpc["subnets"]:
        print(f"Subnet '{subnet_name}' already exists.")
        return

    try:
        subnet = ipaddress.ip_network(subnet_cidr, strict=False)
    except Exception as e:
        print(f"Invalid CIDR: {e}")
        sys.exit()

    gw_ip = str(subnet.network_address + 1)
    host_ip = str(subnet.network_address + 2)
    gw_cidr = f"{gw_ip}/{subnet.prefixlen}"
    host_cidr = f"{host_ip}/{subnet.prefixlen}"
    
    bridge = vpc["bridge"]
    ns_name = f"ns-{vpc_name}-{subnet_name}"
    veth_subnet = f"veth-{subnet_name[0:5]}-{subnet_name[-1]}"
    veth_bridge = f"veth-{subnet_name[0:5]}-{subnet_name[-1]}-br" 

    print(f"Creating Namespace {ns_name}")
    run(f"ip netns del {ns_name}", ignore_error=True) #add logic that checks without showing the deletion
    run(f"ip netns add {ns_name}")
    print(f"   ✅ Created namespace: {ns_name}")

    # Creating a veth pair
    print(f"Creating vethpair for  {ns_name}")
    run(f"ip link add {veth_bridge} type veth peer name {veth_subnet}") # connecting both veth pair ends 
    run(f"ip link set {veth_bridge} master {bridge}") #set the veth_router end to the router namespace
    run(f"ip link set {veth_bridge} up")
    # === Assign gateway IP to bridge (in root ns) ===


    run(f"ip link set {veth_subnet} netns {ns_name}") #moving the subnet veth_pair interface into the subnet namespace 
    run(f"ip netns exec {ns_name} ip addr add {host_cidr} dev {veth_subnet}") #attach hostip cidr to the veth_pair interface
    run(f"ip netns exec {ns_name} ip link set {veth_subnet} up") #bringing it up
    run(f"ip netns exec {ns_name} ip link set lo up")
    run(f"ip netns exec {ns_name} ip route add default via {gw_ip}")

    run(f"ip route replace {subnet_cidr} dev {bridge}", ignore_error=True)

    if stype == "public":
        ext_if = get_default_iface()
        run(f"iptables -t nat -A POSTROUTING -s {subnet_cidr} -o {ext_if} -j MASQUERADE", ignore_error=True)

    vpc["subnets"][subnet_name] = {
        "ns": ns_name,
        "cidr": subnet_cidr,
        "gw_ip": gw_ip,
        "host_ip": host_ip,
        "veth_router": veth_bridge,
        "veth_subnet": veth_subnet,
        "type": stype
    }

    print(f"Subnet '{subnet_name}' added to VPC '{vpc_name}' ({stype})")
    save_state()

# =============================================================================
# Part 3: Peering
# =============================================================================
def peer_vpcs(vpc1, vpc2, subnet1_cidr=None, subnet2_cidr=None):
    VPC1 = VPCS[vpc1]
    VPC2 = VPCS[vpc2]
    print(VPC1['cidr'])
    if vpc1 not in VPCS or vpc2 not in VPCS:
        print("One or both VPCs not found.")
        sys.exit(1)
    if vpc1 == vpc2:
        print("Cannot peer VPC with itself.")
        sys.exit(1)

    v1, v2 = VPCS[vpc1], VPCS[vpc2]
    
    bridge1 = VPC1["bridge"]
    bridge2 = VPC2["bridge"]
    pair_id = f"{vpc1}-{vpc2}"
    print(v1)
    print(vpc1[-1:])
    vpc1_cidr = VPC1["cidr"]
    vpc2_cidr = VPC2["cidr"]

    # Avoid duplicate peering
    if any(p["peer"] == vpc2 for p in v1["peers"]):
        print(f"VPCs already peered.")
        return

    veth1 = f"vt-vpc{vpc1[-1:]}-{vpc2[-1:]}-1"
    veth2 = f"vt-vpc{vpc1[-1:]}-{vpc2[-1:]}-2"
    print(veth1)
    print(veth2)

    try:
        run(f"ip link add {veth1} type veth peer name {veth2}", ignore_error=True)
    except:
        print(f"Warning: veth pair {veth1} <-> {veth2} might already exist.")

    run(f"ip link set {veth1} master {bridge1}")
    run(f"ip link set {veth2} master {bridge2}")
    run(f"ip link set {veth1} up")
    run(f"ip link set {veth2} up")

    # Default: allow all subnets
    if not subnet1_cidr:
        subnet1_cidr = list(v1["subnets"].values())[0]["cidr"]
    if not subnet2_cidr:
        subnet2_cidr = list(v2["subnets"].values())[0]["cidr"]

    # Align network addresses properly
    subnet1_network = ipaddress.ip_network(subnet1_cidr, strict=False)
    subnet2_network = ipaddress.ip_network(subnet2_cidr, strict=False)
    vpc1_network = ipaddress.ip_network(vpc1_cidr, strict=False)
    vpc2_network = ipaddress.ip_network(vpc2_cidr, strict=False)
    last_subnet1 = list(vpc1_network.subnets(new_prefix=24))[-1]
    last_subnet2 = list(vpc2_network.subnets(new_prefix=24))[-1]
    gateway_ip1 = list(last_subnet1.hosts())[0] 
    gateway_ip2 = list(last_subnet2.hosts())[0] 


    # Add routes safely using 'replace' to avoid conflicts
    run(f"ip addr add {gateway_ip1}/24 dev {veth1}")
    run(f"ip addr add {gateway_ip2}/24 dev {veth2}")



    # 7. Add routes inside each VPC to reach the other VPC

    run (f"ip route add {vpc2_cidr} via {gateway_ip1} dev {bridge1}")
    run (f"ip route add {vpc1_cidr} via {gateway_ip2} dev {bridge2}")

    # Update state
    v1["peers"].append({"peer": vpc2, "veth": veth1, "remote_cidr": str(subnet2_network)})
    v2["peers"].append({"peer": vpc1, "veth": veth2, "remote_cidr": str(subnet1_network)})

    print(f"Peering established: {vpc1} <-> {vpc2} "
          f"({subnet1_network} <-> {subnet2_network})")
    save_state()

# =============================================================================
# Part 4: Security Groups (Firewall)
# =============================================================================
def apply_security_policy(vpc_name, subnet_name, policy_file):
    if vpc_name not in VPCS:
        print(f"VPC '{vpc_name}' not found.")
        sys.exit(1)
    vpc = VPCS[vpc_name]
    if subnet_name not in vpc["subnets"]:
        print(f"Subnet '{subnet_name}' not found.")
        sys.exit(1)

    subnet = vpc["subnets"][subnet_name]
    ns = subnet["ns"]

    if not os.path.exists(policy_file):
        print(f"Policy file not found: {policy_file}")
        sys.exit(1)

    with open(policy_file) as f:
        policy = json.load(f)

    if policy["subnet"] != subnet["cidr"]:
        print("Policy subnet mismatch.")
        sys.exit(1)

    # Flush old rules
    run(f"ip netns exec {ns} iptables -F INPUT", ignore_error=True)
    run(f"ip netns exec {ns} iptables -P INPUT DROP", ignore_error=True)

    # Apply ingress rules
    for rule in policy.get("ingress", []):
        port = rule["port"]
        proto = rule["protocol"]
        action = rule["action"].upper()
        if action == "ALLOW":
            run(f"ip netns exec {ns} iptables -A INPUT -p {proto} --dport {port} -j ACCEPT")
        elif action == "DENY":
            run(f"ip netns exec {ns} iptables -A INPUT -p {proto} --dport {port} -j DROP")

    # Allow loopback and established
    run(f"ip netns exec {ns} iptables -A INPUT -i lo -j ACCEPT")
    run(f"ip netns exec {ns} iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")

    vpc["firewall_policies"][subnet_name] = policy_file
    print(f"Security policy applied to '{subnet_name}' from {policy_file}")

# =============================================================================
# Part 5: Test Workloads
# =============================================================================
def deploy_web_server(vpc_name, subnet_name):
    if vpc_name not in VPCS or subnet_name not in VPCS[vpc_name]["subnets"]:
        print("VPC or subnet not found.")
        sys.exit(1)

    ns = VPCS[vpc_name]["subnets"][subnet_name]["ns"]
    host_ip = VPCS[vpc_name]["subnets"][subnet_name]["host_ip"]

    # Install mini-httpd if not exists
    run(f"ip netns exec {ns} apt-get update -qq", ignore_error=True)
    run(f"ip netns exec {ns} apt-get install -y python3", ignore_error=True)

    # Start simple HTTP server
    cmd = [
        "ip", "netns", "exec", ns,
        "python3", "-m", "http.server", "80",
        "--directory", "/tmp", "--bind", "0.0.0.0"
    ]
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,   # Discard output
        stderr=subprocess.DEVNULL,   # Discard errors
        preexec_fn=lambda: None      # Ensures it detaches cleanly
    )

    print(f"Started HTTP server in {ns} with PID {process.pid} on {host_ip}:80")

# =============================================================================
# Cleanup
# =============================================================================
def delete_vpc(name):
    if name not in VPCS:
        print(f"VPC '{name}' not found.")
        return

    vpc = VPCS[name]

    # Delete subnets
    for subnet_name, info in list(vpc["subnets"].items()):
        run(f"ip netns del {info['ns']}", ignore_error=True)

    # Delete peering veths
    for peer in vpc["peers"]:
        run(f"ip link del {peer['veth']}", ignore_error=True)

    # Delete router ns and bridge
    # run(f"ip netns del {vpc['router_ns']}", ignore_error=True)
    run(f"ip link set {vpc['bridge']} down", ignore_error=True)
    run(f"ip link del {vpc['bridge']}", ignore_error=True)

    del VPCS[name]
    print(f"VPC '{name}' fully deleted.")
    save_state()

# =============================================================================
# Show & Status
# =============================================================================
def show_vpcs():
    if not VPCS:
        print("No VPCs created.")
        return
    for name, vpc in VPCS.items():
        print(f"\nVPC: {name} (CIDR: {vpc['cidr']})")
        print(f"  Bridge: {vpc['bridge']}")
        print(f"  Router NS: {vpc['router_ns']}")
        print(f"  Subnets:")
        for sname, s in vpc["subnets"].items():
            print(f"    - {sname}: {s['cidr']} ({s['type']}) → {s['host_ip']}")
        print(f"  Peers: {', '.join(p['peer'] for p in vpc['peers']) or 'none'}")
        print(f"  Firewall Policies: {len(vpc['firewall_policies'])} applied")

# =============================================================================
# Main CLI
# =============================================================================
def main():
    parser = argparse.ArgumentParser(prog="vpcctl", description="Advanced VPC Controller")
    sub = parser.add_subparsers(dest="cmd", required=True)

    # create-vpc
    c1 = sub.add_parser("create-vpc")
    c1.add_argument("name")
    c1.add_argument("--cidr", required=True)

    # add-subnet
    c2 = sub.add_parser("add-subnet")
    c2.add_argument("vpc_name")
    c2.add_argument("subnet_name")
    c2.add_argument("--cidr", required=True)
    c2.add_argument("--type", choices=["public", "private"], default="private")

    # peer-vpcs
    c3 = sub.add_parser("peer-vpcs")
    c3.add_argument("vpc1")
    c3.add_argument("vpc2")
    c3.add_argument("--subnet1-cidr", help="Allow only this CIDR from vpc1")
    c3.add_argument("--subnet2-cidr", help="Allow only this CIDR from vpc2")

    # apply-policy
    c4 = sub.add_parser("apply-policy")
    c4.add_argument("vpc_name")
    c4.add_argument("subnet_name")
    c4.add_argument("policy_file", help="JSON policy file")

    # deploy-web
    c5 = sub.add_parser("deploy-web")
    c5.add_argument("vpc_name")
    c5.add_argument("subnet_name")

    # delete-vpc
    c6 = sub.add_parser("delete-vpc")
    c6.add_argument("name")

    # show
    c7 = sub.add_parser("show")

    args = parser.parse_args()

    if args.cmd == "create-vpc":
        create_vpc(args.name, args.cidr)
    elif args.cmd == "add-subnet":
        add_subnet(args.vpc_name, args.subnet_name, args.cidr, args.type)
    elif args.cmd == "peer-vpcs":
        peer_vpcs(args.vpc1, args.vpc2, args.subnet1_cidr, args.subnet2_cidr)
    elif args.cmd == "apply-policy":
        apply_security_policy(args.vpc_name, args.subnet_name, args.policy_file)
    elif args.cmd == "deploy-web":
        deploy_web_server(args.vpc_name, args.subnet_name)
    elif args.cmd == "delete-vpc":
        delete_vpc(args.name)
    elif args.cmd == "show":
        show_vpcs()

if __name__ == "__main__":
    main()