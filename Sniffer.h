#include <conio.h>
#include <iostream>
#include <iomanip>
#include <Winsock2.h>
#include <WS2tcpip.h>
#include <string>
#include <vector>
#include <windows.h>
#include <time.h>
#include <bitset>
#include <Mstcpip.h>
#include <fstream>
#include <iphlpapi.h>
#include <psapi.h>
#include <algorithm>
#include <sstream>
#include <chrono>
using namespace std;

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")


                                   // описание глобальных переменных


extern WSADATA wsData;             // информация о версии сокетов в ОС
extern SOCKET s;                   // создание сокета 
extern wstring previous_name;      // имя процесса у предыдущего захваченного пакета



                                   // описание структур


#pragma pack(push, 1)
typedef struct // Структура ip пакета
{
	BYTE   ip_ver_hlen;            // версия протокола и длина заголовка (4 + 4 бита)
	BYTE   ip_tos;                 // тип сервиса
	UINT16 ip_length;              // общая длина пакета в байтах
	UINT16 ip_id;                  // идентификатор пакета
	UINT16 ip_flag_offset;         // флаги и смещение фрагмента(3 + 13 бит)
	BYTE   ip_ttl;                 // TTL
	BYTE   ip_protocol;            // протокол верхнего уровня
	UINT16 ip_crc;                 // контрольная сумма
	UINT32 ip_src_addr;            // ip-адрес источника
	UINT32 ip_dst_addr;            // ip-адрес назначения
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

typedef struct // Структура глобального заголовка pcap-файла  
{
	UINT32 magic_number;           // магическое число
	UINT16 version_major;          // номер основной версии формата файла
	UINT16 version_minor;          // номер промежуточной версии формата файла
	int    thiszone;               // часовой пояс
	UINT32 sigfigs;                // точность временных меток
	UINT32 snaplen;                // максимальная длина пакета
	UINT32 network;                // параметр канального уровня (способ передачи данных)
} pcap_hdr;

typedef struct // Структура заголовка каждого пакета для pcap-файла
{
	UINT32 ts_sec;                 // временная отметка (секунды)
	UINT32 ts_usec;                // временная отметка (миллисекунды)
	UINT32 incl_len;               // записанная длина пакета
	UINT32 orig_len;               // фактическая длина пакета
} pcappack_hdr;

typedef struct // Структура для сохранения заголовков пакетов
{	
	IPHeader  ipheader;            // заголовок IP
	TCPHeader tcpheader;           // заголовок TCP
	UDPHeader udpheader;	       // заголовок UDP
} temp_buf;
#pragma pack(pop)



                                   // описание функций


void error_exit(int);                           // печать в консоль сообщения об ошибки в зависимости от её типа

void ShowIPHeaderInfo(IPHeader*);               // вывод в консоль информации из заголовка IP

void ShowTCPHeaderInfo(TCPHeader*);             // вывод в консоль информации из заголовка TCP

void ShowUDPHeaderInfo(UDPHeader*);             // вывод в консоль информации из заголовка UDP

void ShowPacketData(IPHeader*, vector<BYTE>&);  // печать в консоль IP пакета в формате hex и ASCII

// печать в консоль информации о пакете в одну строку (краткий вывод)
void print_info(int, IPHeader*, TCPHeader*, UDPHeader*, wstring&);

// подробная печать в консоль информации о пакете (заголовок IP + TCP/UDP + пакет в формате hex и ASCII)
void print_packet(int, IPHeader*, TCPHeader*, UDPHeader*, wstring&, vector<BYTE>&);

wstring GetProcessNameByPID(DWORD);             // получение имени процесса по PID

// поиск связки IP+порт захваченного TCP пакета в таблице TCP-соединений
wstring GetTcpProcessName(IPHeader*, TCPHeader*, wstring&);

// поиск связки IP+порт захваченного UDP пакета в таблице UDP-соединений
wstring GetUdpProcessName(IPHeader*, UDPHeader*, wstring&);

void init_gen_pcap_header(pcap_hdr*);           // инициализация структуры глобального заголовка pcap

void writehead_to_pcap(HANDLE&);                // запись глобального заголовка в pcap-файл

// запись захваченного пакета и его pcap-заголовка в pcap-файл
void writepack_to_pcap(HANDLE&, vector<BYTE>, UINT16, wstring&);

int isDNS(TCPHeader*, UDPHeader*);              // проверка, захвачен dns-пакет или нет