#include <conio.h>
#include <iostream>
#include <iomanip>
#include <Winsock2.h>
#include <WS2tcpip.h>
#include <string>
#include <vector>
#include <windows.h>
#include <bitset>
#include <Mstcpip.h>
#include <fstream>
#include "sniffer.h"
using namespace std;

#pragma comment(lib, "Ws2_32.lib")

void ShowIPHeaderInfo(IPHeader* iph)    // вывод информации из заголовка IP
{
	cout << "----------- IP Header Information -----------" << endl << endl;
	cout << "Version: " << (UINT)(iph->ip_ver_hlen >> 4) << endl;
	cout << "Header Length: " << dec << (UINT)((iph->ip_ver_hlen & 15)*4) << endl;
	cout << "ToS: " << bitset<8>(iph->ip_tos) << endl;
	cout << "Total Length: " << dec << ntohs(iph->ip_length) << endl;
	cout << "Identification: " << dec << ntohs(iph->ip_id) << endl;
	cout << "Flags: " << endl;
	bitset<3> flags(ntohs(iph->ip_flag_offset) >> 13);
	cout << "\tReserved bit:   " << flags[2] << endl;
	cout << "\tDon't fragment: " << flags[1] << endl;
	cout << "\tMore fragments: " << flags[0] << endl;
	cout << "Fragment Offset: " << dec << (ntohs(iph->ip_flag_offset) & 8191) << endl;
	cout << "TTL: " << dec << (UINT)iph->ip_ttl << endl;
	cout << "Protocol: ";

	switch(iph->ip_protocol){
		case IPPROTO_TCP:
			cout << "TCP" << endl;
			break;
		case IPPROTO_UDP:
			cout << "UDP" << endl;
			break;
		default:
			cout << "Unknown" << endl;
	}

	cout << "Header Checksum: 0x"  << hex << ntohs(iph->ip_crc) << endl;
	in_addr ipaddr; char buf_ip[20];
	ipaddr.s_addr = iph->ip_src_addr;
	cout << "Source: " << inet_ntop(AF_INET, &ipaddr, buf_ip, 16) << endl;
	ipaddr.s_addr = iph->ip_dst_addr;
	cout << "Destination: " << inet_ntop(AF_INET, &ipaddr, buf_ip, 16) << endl << endl;
}

void ShowTCPHeaderInfo(TCPHeader* tcph)    // вывод информации из заголовка TCP
{
	cout << "----------- TCP Header Information -----------" << endl << endl;
	cout << "Source Port: " << dec << ntohs(tcph->tcp_srcport) << endl;
	cout << "Destination Port: " << dec << ntohs(tcph->tcp_dstport) << endl;
	cout << "Sequence Number: " << dec << ntohl(tcph->tcp_seq) << endl;
	cout << "Acknowledgment Number: " << dec << ntohl(tcph->tcp_ack) << endl;
	cout << "Header Length: " << dec << (UINT)((ntohs(tcph->tcp_hlen_flags) >> 12)*4) << endl;
	cout << "Flags: " << endl;
	bitset<6> flags(ntohs(tcph->tcp_hlen_flags) & 63);
	cout << "\tUrgent:          " << flags[5] << endl;
	cout << "\tAcknowledgement: " << flags[4] << endl;
	cout << "\tPush:            " << flags[3] << endl;
	cout << "\tReset:           " << flags[2] << endl;
	cout << "\tSyn:             " << flags[1] << endl;
	cout << "\tFin:             " << flags[0] << endl;
	cout << "Window Size: " << dec << ntohs(tcph->tcp_window) << endl;
	cout << "Checksum: 0x" << hex << ntohs(tcph->tcp_crc) << endl;
	cout << "Urgent Pointer: " << dec << ntohs(tcph->tcp_urg_pointer) << endl << endl;
}

void ShowUDPHeaderInfo(UDPHeader* udph)    // вывод информации из заголовка UDP
{
	cout << "----------- UDP Header Information -----------" << endl << endl;
	cout << "Source Port: " << dec << ntohs(udph->udp_srcport) << endl;
	cout << "Destination Port: " << dec << ntohs(udph->udp_dstport) << endl;
	cout << "Length: " << dec << ntohs(udph->udp_length) << endl;
	cout << "Checksum: 0x" << hex << ntohs(udph->udp_xsum) << endl << endl;
}

void ShowPacketData(IPHeader* iph, vector<BYTE> &Buffer)  // печать IP пакета в формате hex и ASCII
{
	cout << "--------------- IP packet data ----------------" << endl << endl;
	int ip_len = ntohs(iph->ip_length);
	int added = 16 - ip_len%16;
	for(int j=0; j<(ip_len + added); j++) {
		if (j >= ip_len)
		  printf("   ");
		else
		if (Buffer[j]<=15)
		  printf("0%X ", Buffer[j]);
		else
		  printf("%X ", Buffer[j]);

		if ((j+1)%16 ==0 && j!=0) {
		  printf("\t\t");
		  for (int z = j-15; z<=j; z++)
			if ((Buffer[z] < 32 || Buffer[z] > 126) && (z < ip_len))
			   printf(".");
			else
			   printf("%c", Buffer[z]);
		  printf("\n\n");
		}
	}
}

void print_info(int count, IPHeader* iph, TCPHeader* tcph, UDPHeader* udph, string &str)
{
	in_addr ipaddr; char buf_ip[20];	

	if (count == 1) {
		cout << "#    " << "src_ip           " << "dst_ip           " << "protocol   ";
	    cout << "src_port    " << "dst_port    " << "Process                          " << endl;
	}

	ipaddr.s_addr = iph->ip_src_addr;
	inet_ntop(AF_INET, &ipaddr, buf_ip, 16);
	cout << left << setw(5) << count << left << setw(17) << buf_ip;

	ipaddr.s_addr = iph->ip_dst_addr;
	inet_ntop(AF_INET, &ipaddr, buf_ip, 16);
	cout << left << setw(17) << buf_ip;

	if (iph->ip_protocol == IPPROTO_TCP)
		cout << left << setw(11) << "TCP" << setw(12) << ntohs(tcph->tcp_srcport) << setw(12) << ntohs(tcph->tcp_dstport); else
	if (iph->ip_protocol == IPPROTO_UDP)
		cout << left << setw(11) << "UDP" << setw(12) << ntohs(udph->udp_srcport) << setw(12) << ntohs(udph->udp_dstport);
	
	str.erase(0, 1);
	if (str[0] == '[' || str[0] == ' ') str.erase(0, 1);
	if (!str.empty() && str.back() == ']') str.pop_back();
	cout << left << setw(34) << str << endl;	
}

void print_packet(int count, IPHeader* iph, TCPHeader* tcph, UDPHeader* udph, string& str, vector<BYTE>& Buffer)
{
	cout << "---------------- Packet # " << int(count) << " -----------------" << endl << endl;
	str.erase(0, 1);
	if (str[0] == '[' || str[0] == ' ') str.erase(0, 1);
	if (!str.empty() && str.back() == ']') str.pop_back();
	cout << "Packet acssociated with the process: " << str << endl << endl;
	ShowIPHeaderInfo(iph);
	if (iph->ip_protocol == IPPROTO_TCP)
		ShowTCPHeaderInfo(tcph); else
	if (iph->ip_protocol == IPPROTO_UDP)
		ShowUDPHeaderInfo(udph);
	ShowPacketData(iph, Buffer);
	cout << "\n\n\n\n";
}

int main(int argc, char *argv[])
{
	WSADATA wsData;
	int err;

	HANDLE hInput = GetStdHandle(STD_INPUT_HANDLE);    //отключаем режим быстрого редактирования в консоли
	DWORD prevConsoleMode;  
	GetConsoleMode(hInput, &prevConsoleMode);
	SetConsoleMode(hInput, prevConsoleMode & ENABLE_EXTENDED_FLAGS);
	
	err = WSAStartup(MAKEWORD(2,2), &wsData);
	if (err != 0) {
		cout << endl << "Error WinSock version initialization: #" << WSAGetLastError() << endl;
		system("pause");
		exit(1);
	}

	SOCKET s = socket(AF_INET, SOCK_RAW, 0);
	if (s == INVALID_SOCKET) {
		cout << endl << "Error socket initialization: #" << WSAGetLastError() << endl;
		closesocket(s);
		WSACleanup();
		system("pause");
		exit(2);
	}

	char host_buf[256];
	addrinfo hints = {}, *addrs, *addr;
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_RAW;
	hints.ai_protocol = IPPROTO_IP;

	err = gethostname(host_buf, sizeof(host_buf));
	if (err == -1) {
		perror("\nError get the hostname: #");
		closesocket(s);
		WSACleanup();
		system("pause");
		exit(3);
	}

	err = getaddrinfo(host_buf, 0, &hints, &addrs);
	if (err != 0)  {
		cout << endl << "Error get the list of IP-adresses: #" << gai_strerror(err) << endl;
		closesocket(s);
		WSACleanup();
		system("pause");
		exit(4);
	}
	
	cout << "Select the interface to capture:" << endl << endl;
	
	char count = '1';
	vector<sockaddr *> ip(10);	
	for (addr = addrs; addr != NULL; addr = addr->ai_next) {
		ip[count - '0'] = addr->ai_addr; char buf_ip[20];
		cout << count << ". " << inet_ntop(AF_INET, &((sockaddr_in*)ip[count - '0'])->sin_addr, buf_ip, 16) << endl;
		count++;
	}
	
	char num;
    cout << endl << "Please, enter the number of interface: ";
	do
	{   
		num = _getche();
	}   while (num >= count || num < '1');

	err = bind(s, ip[num - '0'], sizeof(sockaddr));
	if (err != 0)  {
		cout << endl << "Error socket binding: #" << WSAGetLastError() << endl;
		closesocket(s);
		WSACleanup();
		system("pause");
		exit(5);
	}
	
	freeaddrinfo(addrs);

	ULONG flag = RCVALL_ON; ULONG z = 0;
	err = WSAIoctl(s, SIO_RCVALL, &flag, sizeof(flag), NULL, 0, &z, NULL, NULL);
	if (err == SOCKET_ERROR) {
		cout << endl << "Error WSAIoctl function: #" << WSAGetLastError() << endl;
		closesocket(s);
		WSACleanup();
		system("pause");
		exit(6);
	}

	cout << "\n\n\n\n" << "1. Full print (IP, TCP/UDP headers + Packet Data)" << endl;
	cout << "2. Short print in single-line format" << endl << endl;
	cout << "Please, select the print packet mode: ";
	do
	{
		num = _getche();
	} while (num != '1' && num != '2');
	
	int p_count = 0;
	cout << "\n\n\n\n" << "Start packet capture...  [ TO STOP capture PRESS ANY KEY ]" << endl << endl;

	while( !_kbhit() ) //захват пакетов
	{
		vector<BYTE> Buffer(65535);	 string port_src, port_dst;
		IPHeader* iph = NULL;  TCPHeader* tcph = NULL;  UDPHeader* udph = NULL;
		in_addr ipaddr; string src_ip, dst_ip, proto;

 		int byte_rcv = recvfrom(s, (char*)&Buffer[0], (int)Buffer.size(), 0, NULL, 0);
		if (byte_rcv >= sizeof(IPHeader))
		{
			iph = (IPHeader *)&Buffer[0];
			UINT ip_hlen = (UINT)((iph->ip_ver_hlen & 15)*4);

			ipaddr.s_addr = iph->ip_src_addr;
			src_ip = inet_ntop(AF_INET, &ipaddr, (char*)(src_ip.c_str()), 16);
			ipaddr.s_addr = iph->ip_dst_addr;
			dst_ip = inet_ntop(AF_INET, &ipaddr, (char*)dst_ip.c_str(), 16);
			src_ip.push_back(':'); dst_ip.push_back(':');

			if(iph->ip_protocol == IPPROTO_TCP) {
				tcph = (TCPHeader *)(&Buffer[0] + ip_hlen);				
				port_src = to_string(ntohs(tcph->tcp_srcport));
				port_dst = to_string(ntohs(tcph->tcp_dstport));
				proto = "TCP";
			} else

			if(iph->ip_protocol == IPPROTO_UDP) {
				udph = (UDPHeader *)(&Buffer[0] + ip_hlen);				
				port_src = to_string(ntohs(udph->udp_srcport));
				port_dst = to_string(ntohs(udph->udp_dstport));
				proto = "UDP";
			}

			FILE* p = _popen("netstat -nab", "r");
			string str = "";
			ifstream a(p);

			if (iph->ip_protocol == IPPROTO_TCP || iph->ip_protocol == IPPROTO_UDP)
			 while (getline(a, str)) {				
				size_t pos1 = str.find(src_ip+port_src);
				size_t pos2 = str.find(dst_ip+port_dst);				
				size_t pos3 = str.find(proto);
				if ((pos1 != string::npos || pos2 != string::npos) && pos3 != string::npos)  {
					p_count++;

					do					
						getline(a, str);						
					while (str.substr(2, 3) == proto);
											
					if (num == '2')
						print_info(p_count, iph, tcph, udph, str); else
					if (num == '1')
						print_packet(p_count, iph, tcph, udph, str, Buffer);
					break;
				}
			 }			
			_pclose(p);
		}
	}

	cout << "\n\nPacket capture completed!\n\n";
	SetConsoleMode(hInput, prevConsoleMode); //возврат прежних настроек консоли
	closesocket(s);
	WSACleanup();
	system("pause");
	return 0;
}
