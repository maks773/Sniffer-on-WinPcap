#pragma pack(push, 1)
typedef struct //—труктура ip пакета
{
	BYTE   ip_ver_hlen;            // верси€ протокола и длина заголовка (4 + 4 бита)
	BYTE   ip_tos;                 // тип сервиса
	UINT16 ip_length;              // обща€ длина пакета в байтах
	UINT16 ip_id;                  // идентификатор пакета
	UINT16 ip_flag_offset;         // флаги и смещение фрагмента(3 + 13 бит)
	BYTE   ip_ttl;                 // TTL
	BYTE   ip_protocol;            // протокол верхнего уровн€
	UINT16 ip_crc;                 // контрольна€ сумма
	UINT32 ip_src_addr;            // ip-адрес источника
	UINT32 ip_dst_addr;            // ip-адрес назначени€
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
#pragma pack(pop)
