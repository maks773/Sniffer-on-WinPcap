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
#include <thread>
#include <mutex>
using namespace std;

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")


                                   // описание глобальных переменных


extern u_long ip_dev;   // IP-адрес интерфейса захвата
extern pcap_t* handle;  // хэндл интерфейса для захвата


                                   // описание структур


#pragma pack(push, 1)
typedef struct // Структура IP заголовка
{
	BYTE   ip_ver_hlen;            // версия протокола и длина заголовка (4 + 4 бита)
	BYTE   ip_tos;                 // тип сервиса
	UINT16 ip_length;              // общая длина пакета в байтах
	UINT16 ip_id;                  // идентификатор пакета
	UINT16 ip_flag_offset;         // флаги и смещение фрагмента(3 + 13 бит)
	BYTE   ip_ttl;                 // TTL
	BYTE   ip_protocol;            // протокол верхнего уровня
	UINT16 ip_crc;                 // контрольная сумма
	UINT32 ip_src_addr;            // IP-адрес источника
	UINT32 ip_dst_addr;            // IP-адрес назначения
} IPHeader;

typedef struct // Структура TCP заголовка
{
	UINT16 tcp_srcport;            // порт источника
	UINT16 tcp_dstport;            // порт отправителя
	UINT32 tcp_seq;                // порядковый номер
	UINT32 tcp_ack;                // номер подтверждения
	UINT16 tcp_hlen_flags;         // длина заголовка, резерв и флаги (4 + 6 + 6 бит)
	UINT16 tcp_window;             // размер окна
	UINT16 tcp_crc;                // контрольная сумма
	UINT16 tcp_urg_pointer;        // указатель срочности
} TCPHeader;

typedef struct // Структура UDP заголовка
{
	UINT16 udp_srcport;            // порт источника
	UINT16 udp_dstport;            // порт отправителя
	UINT16 udp_length;             // общая длина пакета в байтах
	UINT16 udp_xsum;               // контрольная сумма
} UDPHeader;

typedef struct // Структура для сохранения заголовков пакетов
{	
	IPHeader  ipheader;            // заголовок IP
	TCPHeader tcpheader;           // заголовок TCP
	UDPHeader udpheader;	       // заголовок UDP
} temp_buf;
#pragma pack(pop)


                                   // описание функций


void error_exit(int);                           // печать в консоль сообщения об ошибки в зависимости от её типа

void ShowIPHeaderInfo(IPHeader*);               // вывод в консоль информации из заголовка IP (написал для отладки)

void ShowTCPHeaderInfo(TCPHeader*);             // вывод в консоль информации из заголовка TCP (написал для отладки)

void ShowUDPHeaderInfo(UDPHeader*);             // вывод в консоль информации из заголовка UDP (написал для отладки)

void ShowPacketData(IPHeader*, vector<BYTE>&);  // печать в консоль IP пакета в формате hex и ASCII (для отладки)

// печать в консоль информации о пакете в одну строку (краткий вывод)
void print_info(int, IPHeader*, TCPHeader*, UDPHeader*, wstring&);

// подробная печать в консоль информации о пакете (заголовок IP + TCP/UDP + пакет в формате hex и ASCII)
// использовал во время отладки программы
void print_packet(int, IPHeader*, TCPHeader*, UDPHeader*, wstring&, vector<BYTE>&);

wstring GetProcessNameByPID(DWORD);             // получение имени процесса по PID

// поиск связки IP+порт захваченного TCP пакета в таблице TCP-соединений
wstring GetTcpProcessName(IPHeader*, TCPHeader*, wstring&);

// поиск связки IP+порт захваченного UDP пакета в таблице UDP-соединений
wstring GetUdpProcessName(IPHeader*, UDPHeader*, wstring&);

int isDNS(TCPHeader*, UDPHeader*);                            // проверка, захвачен DNS-пакет или нет

boolean isTCPSyn(TCPHeader*);                                 // проверка, установлен ли флаг SYN в TCP-пакете

void print_summary(int capture_packets, int saved_packets);   // вывод итоговой информации после захвата

wstring find_in_prev_socket(IPHeader*, TCPHeader*);           // поиск информации о процессе в предыдущих пакетах

void print_help();                                            // печать "help"

// вывод и сохранение списка доступных для захвата интерфейсов, возвращает количество таких интерфейсов
char print_ifaces(vector<string>&, vector<u_long>&, int argc, int flag); 

// функция для сохранения в память захваченных пакетов (описание функции - в файле Sniffer.cpp)
void process_packet(u_char*, const struct pcap_pkthdr*, const u_char*);

// функция второго потока, который параллельно захвату новых пакетов (в функции process_pcaket)
// производит их анализ (описание функции - в файле Sniffer.cpp)
void threadFunction(u_char*, vector<pcap_pkthdr>&, vector<vector<u_char>>&);

// функция, повышающая привилегии в системе до отладочных (для получения полного доступа к процессам)
void setPrivilege();