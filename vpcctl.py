#!/usr/bin/env python3
import argparse #used for buildimg command line interfaces in python and allowing parsing of command line arguments like vpcctl create-vpc myvpc --cidr
import subprocess #bridge between python and system shell commands(linux commands) allows you use python to run shell commands like ip link add br-myvpc type bridge
import sys #provides access to some variables used or maintained by the interpreter and to functions that interact strongly with the interpreter like sys.exit() to exit the program
import ipaddress #module for creating, manipulating and validating IP addresses and networks

#story
#so to crete a vpc we need to create a linux bridge that will act as the vpc router, the central hub
#this router is what switches/routes traffic between subnets in our vpc
#the subnets are created usinng network namespaces which are like lightweight virtual machines
#each subnet gets a veth pair that connects it to the bridge(router), allowing communication between subnets and the router
#by default, network namespaces are isolated from each other and the host system so they cannot communicate unless we set up routing through the bridge using veth pairs
#when creating the veth pairs, after running the command run(f"ip link add {veth_host} type veth peer name {veth_ns}"), you have two ends of a virtual cable,
#none of the ends are connected yet but when we run the command run(f"ip link set {veth_host} master {bridge_name}") and run(f"ip link set {veth_host} up"), and run(f"ip link set {veth_ns} netns {ns_name}")
#one end (veth_host) is attached to the bridge(router) and the other end (veth_ns) is moved into the subnet's network namespace
#inside the namespace, we assign an IP address to the veth_ns interface and bring it up so it can send/receive traffic
#finally, we set a default route inside the namespace to point to the bridge's IP, allowing the subnet to route traffic through the VPC router to other subnets or external networks




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
    print(f"Creating VPC '{name}' with CIDR {cidr}...")

    # 1️⃣ Create a Linux bridge
    run(f"ip link add {bridge_name} type bridge")
    print(f"   ✅ {name} bridge created.")

    # 2️⃣ Assign an IP address to the bridge (acts like router IP)
    router_ip = str(vpc_net.network_address + 1) #vpc_net.network_address gets the network address of the cidr provided and 1 is added to it, note for the addition to work 
    #it has to be converted to a specific ip address type like IPv4Address or IPv6Address
    router_cidr = f"{router_ip}/{vpc_net.prefixlen}" 
    run(f"ip address add {router_cidr} dev {bridge_name}")#creates the router cidr by combining the router ip and the prefix length of the vpc network
        #what is router cidr? it is the ip address of the bridge interface
        #what is router ip? it is the first usable ip address in the vpc range
    print(f"   ✅ Assigned router IP: {router_cidr} to bridge {name}")
    


    # 3️⃣ Bring bridge interface up
    run(f"ip link set {bridge_name} up")
    print(f"   ✅ {name} is now up and running.")

    #this function creates a VPC by creating a Linux bridge using the ip command
    #it assigns an IP address(the first IP address) to the bridge which acts as the router IP for the VPC
    #finally it brings the bridge interface up to make it operational
    print(f"✨ VPC '{name}' created successfully.")

def add_subnet(vpc_name, subnet_name, subnet_cidr):
    #first ip address in a subnet is the network address ie it identifies the subnet itself
    #second ip address is usually assigned to the router or gateway interface that connects the subnet to other networks
    #third ip address is assigned to the first host or device within the subnet, this time we are assigning it to the veth pair port inside the subnet namespace so any device in the subnet can use receive traffic through this ip address
    #the last ip address is the broadcast address used to send messages to all devices within the subnet
    #anyother ip can b used for hosts/devices in the subnet
    """Create a subnet namespace connected to the VPC bridge."""
    bridge_name = f"br-{vpc_name}" #setting the bridge name the subnet will be created in for now we use the vpc created earlier
    ns_name = f"ns-{subnet_name}"  #creating the namespace name for the subnet
    veth_host = f"veth-{subnet_name}-br" #veth pair names (pair-end on the bridge side)
    veth_ns = f"veth-{subnet_name}-ns" #veth pair names (pair-end on the namespace side)

    subnet_net = ipaddress.ip_network(subnet_cidr, strict=False) #This creates an IP network object representing all the IPs from 10.0.1.0 to 10.0.1.255 (with /24 meaning 256 total addresses, including network and broadcast).
    router_ip_on_subnet = str(subnet_net.network_address + 1) #this is saying that the second IP ie neworkaddr+1 is the router ip on the subnet, it represents the interface of the router or bridge that connects this subnet to others.
    #it is the gateway for devices in this subnet to reach other networks ie other subnets or the internet, so if i want to access another subnet from this subnet, i will send the traffic to this router ip first
    host_ip_in_subnet = str(subnet_net.network_address + 2) 
    host_cidr = f"{host_ip_in_subnet}/{subnet_net.prefixlen}"

    #note subnet doesnt have a single ip address like a router or bridge, it is a range of ip addresses
    cidr = host_cidr #this is the ip address assigned to the veth_ns interface inside the namespace so any device in the subnet can use receive traffic through this ip address ie the ip address of the of the veth_pair port inside the subnet


    print(f"Adding subnet '{subnet_name}' ({subnet_cidr}) to VPC '{vpc_name}'...")

    # 1️⃣ Create the network namespace
    run(f"ip netns del {ns_name}", ignore_error=True) #delete if already exists to avoid error
    run(f"ip netns add {ns_name}") #if the name length exceeds 15 characters, it will throw an error
    #this creates a new network namespace which is like a lightweight virtual machine that provides isolation for the subnet
    #this namespace will have its own network stack, interfaces, and routing table
    #the reason why we there is error if it exceeds 15 characters is because if we attach the veth pair prefix and suffix to the public subnet name
    #to make the veth pair names, it will exceed the 15 character limit for network interface names in linux

    # 2️⃣ Create a veth pair
    run(f"ip link add {veth_host} type veth peer name {veth_ns}")

    # 3️⃣ Attach one end to the bridge
    run(f"ip link set {veth_host} master {bridge_name}")
    run(f"ip link set {veth_host} up") #bring up the veth_host interface to make it operational, default state is down

    # 4️⃣ Move the other end into the namespace to connect to subnet
    run(f"ip link set {veth_ns} netns {ns_name}")

    # 5️⃣ Assign IP and bring up interfaces inside namespace
    run(f"ip netns exec {ns_name} ip addr add {cidr} dev {veth_ns}") #assigns IP to the veth_ns inside the namespace ie the veth_pair port inside the subnet
    run(f"ip netns exec {ns_name} ip link set {veth_ns} up") #bring up the veth_ns interface inside the namespace to make it operational
    run(f"ip netns exec {ns_name} ip link set lo up") #bring up the loopback interface inside the namespace
    # Every Linux network stack has a lo (loopback) interface — IP address 127.0.0.1
    # So this ensures that internal services can use 127.0.0.1.
    # If you don’t bring it up, many network applications won’t work properly inside the namespace, because they often expect to bind to localhost.

    # 6️⃣ Add a default route via bridge
    run(f"ip netns exec {ns_name} ip route add default via {router_ip_on_subnet}") #default gateway/route to the bridge/router IP
    # run(f"ip netns exec {ns_name} ip route add default via {cidr.split('.')[0]}.0.0.1") #default gateway/route to the bridge/router IP
    #so any route that is not for local should be sent to the bridge using this 

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

    # vpcctl add-subnet myvpc public --cidr 10.0.1.1/24
    subnet_parser = subparsers.add_parser("add-subnet")
    subnet_parser.add_argument("vpc_name")
    subnet_parser.add_argument("subnet_name")
    subnet_parser.add_argument("--cidr", required=True)

    # vpcctl delete-vpc myvpc
    delete_parser = subparsers.add_parser("delete-vpc")
    delete_parser.add_argument("name")

    args = parser.parse_args()

    if args.command == "create-vpc":
        create_vpc(args.name, args.cidr)
    elif args.command == "add-subnet":
        add_subnet(args.vpc_name, args.subnet_name, args.cidr)
    elif args.command == "delete-vpc":
        delete_vpc(args.name)
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()



#ip link show: this list all the network bridges 
# ip addr show br-main-br: this shows the details of the bridge including its IP address
# ip netns list: this lists all the network namespaces (subnets) created