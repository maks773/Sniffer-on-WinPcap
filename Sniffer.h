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


                                   // описание структур


#pragma pack(push, 1)
typedef struct // —труктура IP заголовка
{
	BYTE   ip_ver_hlen;            // верси€ протокола и длина заголовка (4 + 4 бита)
	BYTE   ip_tos;                 // тип сервиса
	UINT16 ip_length;              // обща€ длина пакета в байтах
	UINT16 ip_id;                  // идентификатор пакета
	UINT16 ip_flag_offset;         // флаги и смещение фрагмента(3 + 13 бит)
	BYTE   ip_ttl;                 // TTL
	BYTE   ip_protocol;            // протокол верхнего уровн€
	UINT16 ip_crc;                 // контрольна€ сумма
	UINT32 ip_src_addr;            // IP-адрес источника
	UINT32 ip_dst_addr;            // IP-адрес назначени€
} IPHeader;

typedef struct // —труктура TCP заголовка
{
	UINT16 tcp_srcport;            // порт источника
	UINT16 tcp_dstport;            // порт отправител€
	UINT32 tcp_seq;                // пор€дковый номер
	UINT32 tcp_ack;                // номер подтверждени€
	UINT16 tcp_hlen_flags;         // длина заголовка, резерв и флаги (4 + 6 + 6 бит)
	UINT16 tcp_window;             // размер окна
	UINT16 tcp_crc;                // контрольна€ сумма
	UINT16 tcp_urg_pointer;        // указатель срочности
} TCPHeader;

typedef struct // —труктура UDP заголовка
{
	UINT16 udp_srcport;            // порт источника
	UINT16 udp_dstport;            // порт отправител€
	UINT16 udp_length;             // обща€ длина пакета в байтах
	UINT16 udp_xsum;               // контрольна€ сумма
} UDPHeader;

typedef struct // —труктура дл€ сохранени€ заголовков пакетов
{	
	IPHeader  ipheader;            // заголовок IP
	TCPHeader tcpheader;           // заголовок TCP
	UDPHeader udpheader;	       // заголовок UDP
	pcap_pkthdr header;            // заголовок пакета дл€ pcap-файла 
} temp_buf;
#pragma pack(pop)


                                   // описание функций


void error_exit(int);                           // печать в консоль сообщени€ об ошибки в зависимости от еЄ типа

void ShowIPHeaderInfo(IPHeader*);               // вывод в консоль информации из заголовка IP (написал дл€ отладки)

void ShowTCPHeaderInfo(TCPHeader*);             // вывод в консоль информации из заголовка TCP (написал дл€ отладки)

void ShowUDPHeaderInfo(UDPHeader*);             // вывод в консоль информации из заголовка UDP (написал дл€ отладки)

void ShowPacketData(IPHeader*, vector<BYTE>&);  // печать в консоль IP пакета в формате hex и ASCII (дл€ отладки)

// печать в консоль информации о пакете в одну строку (краткий вывод)
void print_info(int, IPHeader*, TCPHeader*, UDPHeader*, wstring&);

// подробна€ печать в консоль информации о пакете (заголовок IP + TCP/UDP + пакет в формате hex и ASCII)
// использовал во врем€ отладки программы
void print_packet(int, IPHeader*, TCPHeader*, UDPHeader*, wstring&, vector<BYTE>&);

wstring GetProcessNameByPID(DWORD);             // получение имени процесса по PID

// поиск св€зки IP+порт захваченного TCP пакета в таблице TCP-соединений
wstring GetTcpProcessName(IPHeader*, TCPHeader*, wstring&);

// поиск св€зки IP+порт захваченного UDP пакета в таблице UDP-соединений
wstring GetUdpProcessName(IPHeader*, UDPHeader*, wstring&);

int isDNS(TCPHeader*, UDPHeader*);              // проверка, захвачен DNS-пакет или нет

// основна€ функци€ обработки захваченных пакетов (описание в файле Sniffer.cpp)
void process_packet(u_char*, const struct pcap_pkthdr*, const u_char*);