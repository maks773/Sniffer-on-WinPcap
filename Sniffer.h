#include <conio.h>
#include <iostream>
#include <iomanip>
#include <Winsock2.h>
#include <vector>
#include <windows.h>
#include <bitset>
#include <iphlpapi.h>
#include <psapi.h>
#include <algorithm>
#include <sstream>
#include <pcap.h>
using namespace std;

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")


                                   // �������� ��������


#pragma pack(push, 1)
typedef struct // ��������� IP ���������
{
	BYTE   ip_ver_hlen;            // ������ ��������� � ����� ��������� (4 + 4 ����)
	BYTE   ip_tos;                 // ��� �������
	UINT16 ip_length;              // ����� ����� ������ � ������
	UINT16 ip_id;                  // ������������� ������
	UINT16 ip_flag_offset;         // ����� � �������� ���������(3 + 13 ���)
	BYTE   ip_ttl;                 // TTL
	BYTE   ip_protocol;            // �������� �������� ������
	UINT16 ip_crc;                 // ����������� �����
	UINT32 ip_src_addr;            // IP-����� ���������
	UINT32 ip_dst_addr;            // IP-����� ����������
} IPHeader;

typedef struct // ��������� TCP ���������
{
	UINT16 tcp_srcport;            // ���� ���������
	UINT16 tcp_dstport;            // ���� �����������
	UINT32 tcp_seq;                // ���������� �����
	UINT32 tcp_ack;                // ����� �������������
	UINT16 tcp_hlen_flags;         // ����� ���������, ������ � ����� (4 + 6 + 6 ���)
	UINT16 tcp_window;             // ������ ����
	UINT16 tcp_crc;                // ����������� �����
	UINT16 tcp_urg_pointer;        // ��������� ���������
} TCPHeader;

typedef struct // ��������� UDP ���������
{
	UINT16 udp_srcport;            // ���� ���������
	UINT16 udp_dstport;            // ���� �����������
	UINT16 udp_length;             // ����� ����� ������ � ������
	UINT16 udp_xsum;               // ����������� �����
} UDPHeader;

typedef struct // ��������� ��� ���������� ���������� �������
{	
	IPHeader  ipheader;            // ��������� IP
	TCPHeader tcpheader;           // ��������� TCP
	UDPHeader udpheader;	       // ��������� UDP
	pcap_pkthdr header;            // ��������� ������ ��� pcap-����� 
} temp_buf;
#pragma pack(pop)


                                   // �������� �������


void error_exit(int);                           // ������ � ������� ��������� �� ������ � ����������� �� � ����

void ShowIPHeaderInfo(IPHeader*);               // ����� � ������� ���������� �� ��������� IP (������� ��� �������)

void ShowTCPHeaderInfo(TCPHeader*);             // ����� � ������� ���������� �� ��������� TCP (������� ��� �������)

void ShowUDPHeaderInfo(UDPHeader*);             // ����� � ������� ���������� �� ��������� UDP (������� ��� �������)

void ShowPacketData(IPHeader*, vector<BYTE>&);  // ������ � ������� IP ������ � ������� hex � ASCII (��� �������)

// ������ � ������� ���������� � ������ � ���� ������ (������� �����)
void print_info(int, IPHeader*, TCPHeader*, UDPHeader*, wstring&);

// ��������� ������ � ������� ���������� � ������ (��������� IP + TCP/UDP + ����� � ������� hex � ASCII)
// ����������� �� ����� ������� ���������
void print_packet(int, IPHeader*, TCPHeader*, UDPHeader*, wstring&, vector<BYTE>&);

wstring GetProcessNameByPID(DWORD);             // ��������� ����� �������� �� PID

// ����� ������ IP+���� ������������ TCP ������ � ������� TCP-����������
wstring GetTcpProcessName(IPHeader*, TCPHeader*, wstring&);

// ����� ������ IP+���� ������������ UDP ������ � ������� UDP-����������
wstring GetUdpProcessName(IPHeader*, UDPHeader*, wstring&);

int isDNS(TCPHeader*, UDPHeader*);              // ��������, �������� DNS-����� ��� ���

// �������� ������� ��������� ����������� ������� (�������� � ����� Sniffer.cpp)
void process_packet(u_char*, const struct pcap_pkthdr*, const u_char*);