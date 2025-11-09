#!/usr/bin/env python3
import argparse 
import subprocess 
import sys 
import ipaddress 

def run(cmd, ignore_error=False):
    try:
        """Helper function to run shell commands."""
        print(f"Running: {cmd}")
        subprocess.run(
            cmd, 
            shell=True, 
            check=True,
            capture_output=True,
            text=True
        ) #runs the shell command in subsequent functions
    except subprocess.CalledProcessError as e:
        if ignore_error:
            print(f"⚠️ Ignored error for: {cmd}")
            return
        print(f"Command failed: {e}")
        print(f"❌ Error executing command: {' '.join(cmd)}")
        print(f"   Stderr: {e.stderr.strip()}")
        sys.exit(1)
    except FileNotFoundError:
        print(f"❌ Error: Required command not found. Ensure network tools (ip, brctl) are installed.")
        sys.exit(1)


def create_vpc(name, cidr):
    """Create a VPC bridge that acts as a router."""
    bridge_name = f"br-{name}"
    vpc_net = ipaddress.ip_network(cidr, strict=False) #creates an ip_network object from the cidr provided
    router_ns = f"ns-router-{name}"
    print(f"Creating VPC '{name}' with CIDR {cidr}...")

    # === Clean up bridge if exists ===
    result = subprocess.run(
        f"ip link show {bridge_name}", shell=True, capture_output=True, text=True
    )
    if result.returncode == 0:
        print(f"   Bridge {bridge_name} exists. Deleting...")
        run(f"ip link set {bridge_name} down", ignore_error=True)
        run(f"ip link del {bridge_name}", ignore_error=True)

    result = subprocess.run(
        f"ip netns list | grep -w {router_ns}", shell=True, capture_output=True
    )
    if result.returncode == 0:
        print(f"   Router namespace {router_ns} exists. Deleting...")
        run(f"ip netns del {router_ns}", ignore_error=True)
    
    #Create a Linux bridge
    run(f"ip link add {bridge_name} type bridge")
    print(f"   ✅ {name} bridge created.")

    #Assign an IP address to the bridge (acts like router IP)
    router_ip = str(vpc_net.network_address + 1) 
    router_cidr = f"{router_ip}/{vpc_net.prefixlen}" 
    run(f"ip address add {router_cidr} dev {bridge_name}")#creates the router cidr by combining the router ip and the prefix length of the vpc network
    print(f"   ✅ Assigned router IP: {router_cidr} to bridge {name}")

    #Bring bridge interface up
    run(f"ip link set {bridge_name} up")
    print(f"   ✅ {name} is now up and running.")

    # create router namespace for the VPC
    run(f"ip netns add {router_ns}", ignore_error=True)

    # ensure ip forwarding is enabled inside router namespace
    run(f"ip netns exec {router_ns} sysctl -w net.ipv4.ip_forward=1")
    print(f"✨ VPC '{name}' created successfully.")

def enable_nat_on_host(cidr, default_route):
    default_route = subprocess.getoutput("ip route | grep default | awk '{print $5}' | head -1")
    run("sysctl -w net.ipv4.ip_forward=1")
    run(f"iptables -t nat -A POSTROUTING -s {cidr} -o {default_route} -j MASQUERADE")
    print(f"Enabled NAT for {cidr} -> {default_route}")

def add_subnet(vpc_name, subnet_name, subnet_cidr, type):
    """Create a subnet namespace connected to the VPC bridge."""
    bridge_name = f"br-{vpc_name}"
    ns_name = f"ns-{subnet_name}"
    veth_host = f"veth-{subnet_name}-br"
    veth_ns = f"veth-{subnet_name}-ns"

    # New: veth pair for router to join this subnet
    router_ns = f"ns-router-{vpc_name}"
    veth_r_br = f"veth-{subnet_name}-r-br"    # host-side attached to bridge
    veth_r_rt = f"veth-{subnet_name}-r-rt"    # peer moved into router ns

    subnet_net = ipaddress.ip_network(subnet_cidr, strict=False)
    router_ip_on_subnet = str(subnet_net.network_address + 1)
    host_ip_in_subnet = str(subnet_net.network_address + 2) 
    host_cidr = f"{host_ip_in_subnet}/{subnet_net.prefixlen}"
    cidr = host_cidr

    print(f"Adding subnet '{subnet_name}' ({subnet_cidr}) to VPC '{vpc_name}'...")

    #Create the network namespace
    run(f"ip netns del {ns_name}", ignore_error=True) #delete if already exists to avoid error
    run(f"ip netns add {ns_name}")
    print(f"   ✅ Created namespace: {ns_name}")

    # Creating a veth pair
    run(f"ip link add {veth_host} type veth peer name {veth_ns}")
    print(f"   ✅ Created veth pair: {veth_host} <-> {veth_ns}")

    # Attach one end to the bridge
    run(f"ip link set {veth_host} master {bridge_name}")
    run(f"ip link set {veth_host} up") #bring up the veth_host interface to make it operational, default state is down
    print(f"   ✅ Attached {veth_host} to bridge {bridge_name} and brought it up.")

    #Attaching the other end into the namespace to connect to subnet
    run(f"ip link set {veth_ns} netns {ns_name}")
    print(f"   ✅ Moved {veth_ns} into namespace {ns_name}.")

    #Assign IP and bring up interfaces inside namespace
    run(f"ip netns exec {ns_name} ip addr add {cidr} dev {veth_ns}") #assigns IP to the veth_ns inside the namespace ie the veth_pair port inside the subnet
    run(f"ip netns exec {ns_name} ip link set {veth_ns} up") #bring up the veth_ns interface inside the namespace to make it operational
    run(f"ip netns exec {ns_name} ip link set lo up") #bring up the loopback interface inside the namespace

    #Add a default route via bridge
    run(f"ip netns exec {ns_name} ip route add default via {router_ip_on_subnet}") #default gateway/route to the bridge/router IP
    print(f"   ✅ Added default route via {router_ip_on_subnet} in namespace {ns_name}.")
    print(f"   ✅ Assigned IP {cidr} to {veth_ns} and brought it up inside {ns_name}.")

    if type == "public":
        enable_nat_on_host(subnet_cidr, "eth0")

    # NEW: create router veth for this subnet, attach to bridge
    run(f"ip link add {veth_r_br} type veth peer name {veth_r_rt}")
    run(f"ip link set {veth_r_br} master {bridge_name}")
    run(f"ip link set {veth_r_br} up")

    # move router peer into router namespace and assign gateway IP there
    run(f"ip link set {veth_r_rt} netns {router_ns}")
    run(f"ip netns exec {router_ns} ip addr add {router_ip_on_subnet}/{subnet_net.prefixlen} dev {veth_r_rt}")
    run(f"ip netns exec {router_ns} ip link set {veth_r_rt} up")

    print(f"✨ Subnet '{subnet_name}' added to VPC '{vpc_name}' successfully.")

def delete_vpc(name):
    """Tear down the VPC and all its resources."""
    bridge_name = f"br-{name}"
    print(f"Deleting VPC '{name}'...")

    # Delete all subnets/namespaces first
    output = subprocess.getoutput("ip netns list")
    for ns in output.splitlines():
        if ns.startswith("ns-"):
            ns_name = ns.split()[0]
            run(f"ip netns del {ns_name}")

    # Delete bridge
    run(f"ip link set {bridge_name} down")
    run(f"ip link del {bridge_name}")

def main():
    parser = argparse.ArgumentParser(description="Mini VPC Control CLI") #creates the main parser object that will handle command line arguments
    subparsers = parser.add_subparsers(dest="command") #subparsers allow you to create multiple sub-commands for the main command e.g in git add "file.txt". add is a subcommand

    # vpcctl create-vpc myvpc --cidr 10.0.0.1/24
    create_parser = subparsers.add_parser("create-vpc")
    create_parser.add_argument("name")
    create_parser.add_argument("--cidr", required=True)

    # subnet
    subnet_parser = subparsers.add_parser("add-subnet")
    subnet_parser.add_argument("vpc_name")
    subnet_parser.add_argument("subnet_name")
    subnet_parser.add_argument("--cidr", required=True)
    subnet_parser.add_argument("--type", default="private")

    # vpcctl delete-vpc myvpc
    delete_parser = subparsers.add_parser("delete-vpc")
    delete_parser.add_argument("name")

    args = parser.parse_args()

    if args.command == "create-vpc":
        create_vpc(args.name, args.cidr)
    elif args.command == "add-subnet":
        add_subnet(args.vpc_name, args.subnet_name, args.cidr, args.type)
    elif args.command == "delete-vpc":
        delete_vpc(args.name)
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
