#include "sniffer.h"
using namespace std;


vector<pair<MIB_TCPROW_OWNER_PID, wstring>> found_sock_record;    // для хранения найденной записи и связанного процесса


                        // описание функций из заголовочного файла Sniffer.h


void error_exit(int code)
{
	switch (code)
	{
	case 1:  cout << "\nError get interfaces" << endl << endl; break;
	case 2:  cout << "\nError open interface handle" << endl << endl; break;
	case 3:  cout << "\nError create pcap file: " << pcap_geterr(handle) << endl; break;
	case 4:	 cout << "\nError memory allocation in malloc function" << endl << endl; break;
	case 5:  cout << "\nError in GetExtendedTcpTable function" << endl << endl; break;
	case 6:  cout << "\nError in GetExtendedUdpTable function" << endl << endl; break;
	case 7:  cout << "\nError in pcap_loop function: " << pcap_geterr(handle) << endl; break;
	case 8:  cout << "\nError in compile pcap-filter: " << pcap_geterr(handle) << endl; break;
	case 9:  cout << "\nError in set pcap-filter: " << pcap_geterr(handle) << endl; break;
	case 10: cout << "\nError syntax: unknown options" << endl << endl; break;
	}

	cout << endl << endl << "To EXIT press CTRL+C" << endl;

	while (true) cin.get();
}



void ShowIPHeaderInfo(IPHeader* iph)    
{
	cout << "----------- IP Header Information -----------" << endl << endl;
	cout << "Version: " << dec << (UINT)(iph->ip_ver_hlen >> 4) << endl;
	cout << "Header Length: " << dec << (UINT)((iph->ip_ver_hlen & 15) * 4) << endl;
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

	switch (iph->ip_protocol)
	{
	case IPPROTO_TCP:
		cout << "TCP" << endl;
		break;
	case IPPROTO_UDP:
		cout << "UDP" << endl;
		break;
	default:
		cout << "Unknown" << endl;
	}

	cout << "Header Checksum: 0x" << hex << ntohs(iph->ip_crc) << endl;

	in_addr ipaddr; char buf_ip[20];

	ipaddr.s_addr = iph->ip_src_addr;
	cout << "Source: " << inet_ntop(AF_INET, &ipaddr, buf_ip, 16) << endl;

	ipaddr.s_addr = iph->ip_dst_addr;
	cout << "Destination: " << inet_ntop(AF_INET, &ipaddr, buf_ip, 16) << endl << endl;
}



void ShowTCPHeaderInfo(TCPHeader* tcph)    
{
	cout << "----------- TCP Header Information -----------" << endl << endl;
	cout << "Source Port: " << dec << ntohs(tcph->tcp_srcport) << endl;
	cout << "Destination Port: " << dec << ntohs(tcph->tcp_dstport) << endl;
	cout << "Sequence Number: " << dec << ntohl(tcph->tcp_seq) << endl;
	cout << "Acknowledgment Number: " << dec << ntohl(tcph->tcp_ack) << endl;
	cout << "Header Length: " << dec << (UINT)((ntohs(tcph->tcp_hlen_flags) >> 12) * 4) << endl;
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



void ShowUDPHeaderInfo(UDPHeader* udph)  
{
	cout << "----------- UDP Header Information -----------" << endl << endl;
	cout << "Source Port: " << dec << ntohs(udph->udp_srcport) << endl;
	cout << "Destination Port: " << dec << ntohs(udph->udp_dstport) << endl;
	cout << "Length: " << dec << ntohs(udph->udp_length) << endl;
	cout << "Checksum: 0x" << hex << ntohs(udph->udp_xsum) << endl << endl;
}



void ShowPacketData(IPHeader* iph, vector<BYTE>& Buffer)  
{
	cout << "--------------- IP packet data ----------------" << endl << endl;
	int ip_len = ntohs(iph->ip_length);
	int added = 16 - ip_len % 16;
	for (int j = 0; j < (ip_len + added); j++)
	{
		if (j >= ip_len)
			printf("   ");
		else
			if (Buffer[j] <= 15)
				printf("0%X ", Buffer[j]);
			else
				printf("%X ", Buffer[j]);

		if ((j + 1) % 16 == 0 && j != 0)
		{
			printf("\t\t");
			for (int z = j - 15; z <= j; z++)
				if ((Buffer[z] < 32 || Buffer[z] > 126) && (z < ip_len))
					printf(".");
				else
					printf("%c", Buffer[z]);
			printf("\n\n");
		}
	}
}



void print_info(int count, IPHeader* iph, TCPHeader* tcph, UDPHeader* udph, wstring& str)           
{
	in_addr ipaddr; char buf_ip[20];

	if (count == 1)
	{
		cout << "#      " << "src_ip           " << "dst_ip           " << "protocol   ";
		cout << "src_port    " << "dst_port    " << "Process                          " << endl;
	}

	ipaddr.s_addr = iph->ip_src_addr;
	inet_ntop(AF_INET, &ipaddr, buf_ip, 16);
	cout << left << setw(7) << count << left << setw(17) << buf_ip;

	ipaddr.s_addr = iph->ip_dst_addr;
	inet_ntop(AF_INET, &ipaddr, buf_ip, 16);
	cout << left << setw(17) << buf_ip;

	if (iph->ip_protocol == IPPROTO_TCP)
		cout << left << setw(11) << "TCP" << setw(12) << ntohs(tcph->tcp_srcport)
		<< setw(12) << ntohs(tcph->tcp_dstport); else
		if (iph->ip_protocol == IPPROTO_UDP)
			cout << left << setw(11) << "UDP" << setw(12) << ntohs(udph->udp_srcport)
			<< setw(12) << ntohs(udph->udp_dstport);

	wcout << left << setw(34) << str << endl;
}



void print_packet(int count, IPHeader* iph, TCPHeader* tcph, UDPHeader* udph, wstring& str, vector<BYTE>& Buffer)         
{
	cout << "---------------- Packet # " << dec << int(count) << " -----------------" << endl << endl;
	wcout << L"Packet acssociated with the process: " << str << endl << endl;

	ShowIPHeaderInfo(iph);

	if (iph->ip_protocol == IPPROTO_TCP)
		ShowTCPHeaderInfo(tcph); else
		if (iph->ip_protocol == IPPROTO_UDP)
			ShowUDPHeaderInfo(udph);

	ShowPacketData(iph, Buffer);
	cout << "\n\n\n\n";
}



wstring GetProcessNameByPID(DWORD pid)
{
	TCHAR nameProc[MAX_PATH];

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS | PROCESS_QUERY_INFORMATION |
		PROCESS_VM_READ, FALSE, pid);   // открываем хэндл процесса по pid

	if (hProcess == NULL)
		return L"Unknown process";

	if (GetModuleFileNameEx(hProcess, 0, nameProc, MAX_PATH) != NULL)   // ищем имя процесса по хэндлу
	{  
		CloseHandle(hProcess);
		wstring process_name = nameProc;
		size_t pos = process_name.rfind('\\');  // отрезаем лишний путь и берём только имя файла

		if (pos != string::npos)		
			process_name = process_name.substr(pos + 1);

		return process_name;		
	}

	CloseHandle(hProcess);
	return L"Unknown process";
}



wstring GetTcpProcessName(IPHeader* iph, TCPHeader* tcph, wstring& enter_procname) 
{
	PMIB_TCPTABLE_OWNER_PID pTcpTable = (MIB_TCPTABLE_OWNER_PID*)malloc(sizeof(MIB_TCPTABLE_OWNER_PID));
	DWORD dwSize = sizeof(MIB_TCPTABLE_OWNER_PID), dwRetVal = 0;
	if ((dwRetVal = GetExtendedTcpTable(pTcpTable, &dwSize, true, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0))
		== ERROR_INSUFFICIENT_BUFFER)
	{
		free(pTcpTable);
		pTcpTable = (MIB_TCPTABLE_OWNER_PID*)malloc(dwSize);
		if (pTcpTable == NULL)
		{
			free(pTcpTable);
			error_exit(4);
		}
	}

	wstring process_name = L"Unknown process";

	if ((dwRetVal = GetExtendedTcpTable(pTcpTable, &dwSize, true, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0))
		== NO_ERROR)
	{
		for (int i = 0; i < (int)pTcpTable->dwNumEntries; i++)  // ищем связку IP/порт пакета в таблице соединений

			if ((iph->ip_src_addr == pTcpTable->table[i].dwLocalAddr &&
				iph->ip_dst_addr == pTcpTable->table[i].dwRemoteAddr &&
				tcph->tcp_srcport == pTcpTable->table[i].dwLocalPort &&
				tcph->tcp_dstport == pTcpTable->table[i].dwRemotePort) ||
				(iph->ip_src_addr == pTcpTable->table[i].dwRemoteAddr &&
					iph->ip_dst_addr == pTcpTable->table[i].dwLocalAddr &&
					tcph->tcp_srcport == pTcpTable->table[i].dwRemotePort &&
					tcph->tcp_dstport == pTcpTable->table[i].dwLocalPort))
			{
				// когда статус TIME_WAIT и PID = 0, handle не открывается, но процесс есть и связан с одним
				// из предыдущих пакетов

				if (pTcpTable->table[i].dwState != 11 && pTcpTable->table[i].dwOwningPid != 0)
				{
					process_name = GetProcessNameByPID(pTcpTable->table[i].dwOwningPid);

					if (process_name == L"Unknown process")                  // перепроверка на связь пакета с предыдущими,
						process_name = find_in_prev_socket(iph, tcph);       // у которых определено имя процесса 

					int flag = 0;

					for (int z = found_sock_record.size() - 1; z >= 0; z--)  // сохраняем в буфер уникальные сокеты
					{                                                        // без учёта клиентского порта
						if (process_name == L"Unknown process")
						{
							flag = -1;
							break;
						}							
							
						if ((iph->ip_src_addr == found_sock_record[z].first.dwRemoteAddr &&
							tcph->tcp_srcport == found_sock_record[z].first.dwRemotePort) ||
							(iph->ip_dst_addr == found_sock_record[z].first.dwRemoteAddr &&
								tcph->tcp_dstport == found_sock_record[z].first.dwRemotePort))
						{
							flag = -1;
							break;
						}
						
					}

					if (flag != -1) 
						found_sock_record.push_back(make_pair(pTcpTable->table[i], process_name));					
				}
				else
					process_name = find_in_prev_socket(iph, tcph);	 // ищем процесс в предыдущих пакетах			

				free(pTcpTable);

				if (enter_procname == L"NULL" || enter_procname == process_name)
					return process_name;
				else
					return L"Reject";
			}

		if (ip_dev == iph->ip_src_addr || ip_dev == iph->ip_dst_addr)     // на случай, если сокет уже закрыт
		{                                                                 // к моменту обработки пакета
			process_name = find_in_prev_socket(iph, tcph);
		}
		else
			process_name = L"Reject";
                                                 
		free(pTcpTable);
		return process_name;
	}
	else
	{
		free(pTcpTable);
		error_exit(5);
	}
}



wstring GetUdpProcessName(IPHeader* iph, UDPHeader* udph, wstring& enter_procname)
{
	PMIB_UDPTABLE_OWNER_PID pUdpTable = (MIB_UDPTABLE_OWNER_PID*)malloc(sizeof(MIB_UDPTABLE_OWNER_PID));
	DWORD dwSize = sizeof(MIB_UDPTABLE_OWNER_PID), dwRetVal = 0;
	if ((dwRetVal = GetExtendedUdpTable(pUdpTable, &dwSize, true, AF_INET, UDP_TABLE_OWNER_PID, 0))
		== ERROR_INSUFFICIENT_BUFFER)
	{
		free(pUdpTable);
		pUdpTable = (MIB_UDPTABLE_OWNER_PID*)malloc(dwSize);
		if (pUdpTable == NULL)
		{
			free(pUdpTable);
			error_exit(4);
		}
	}

	wstring process_name = L"Unknown process";

	if ((dwRetVal = GetExtendedUdpTable(pUdpTable, &dwSize, true, AF_INET, UDP_TABLE_OWNER_PID, 0))
		== NO_ERROR)
	{
		for (int i = 0; i < (int)pUdpTable->dwNumEntries; i++)  // ищем связку IP/порт пакета в таблице соединений

			if ((iph->ip_src_addr == pUdpTable->table[i].dwLocalAddr &&
				udph->udp_srcport == pUdpTable->table[i].dwLocalPort) ||
				(iph->ip_dst_addr == pUdpTable->table[i].dwLocalAddr &&
					udph->udp_dstport == pUdpTable->table[i].dwLocalPort))
			{
				process_name = GetProcessNameByPID(pUdpTable->table[i].dwOwningPid);

				free(pUdpTable);

				if (enter_procname == L"NULL" || enter_procname == process_name)
					return process_name;
				else
					return L"Reject";
			}

		if (ip_dev != iph->ip_src_addr && ip_dev != iph->ip_dst_addr)
			process_name = L"Reject";

		free(pUdpTable);
		return process_name;
	}
	else
	{
		free(pUdpTable);
		error_exit(6);
	}
}



int isDNS(TCPHeader* tcph, UDPHeader* udph)
{
	if ((tcph != NULL && ntohs(tcph->tcp_dstport) == 53) || (udph != NULL && ntohs(udph->udp_dstport) == 53))
		return 0;      // dns-запрос
	else
		if ((tcph != NULL && ntohs(tcph->tcp_srcport) == 53) || (udph != NULL && ntohs(udph->udp_srcport) == 53))
			return 1;  // dns-ответ
		else
			return 2;  // не dns-пакет
}



boolean isTCPSyn(TCPHeader* tcph)
{
	if (tcph == NULL)
		return false;
	
	bitset<6> flags(ntohs(tcph->tcp_hlen_flags) & 63);

	if (flags[1] == 1)
		return true;
	else
		return false;
}



void print_summary(int capture_packets, int saved_packets)
{
	cout << "\n\nPacket capture completed!\n\n";

	cout << "Captured packets: " << capture_packets << endl;       // cколько всего пакетов захватил драйвер

	cout << "Saved packets to file: " << saved_packets << endl;    // сколько пакетов сохранили в файл

	cout << endl << "To EXIT press CTRL+C" << endl;                // для завершения работы программы
}



wstring find_in_prev_socket(IPHeader* iph, TCPHeader* tcph)
{
	for (int z = found_sock_record.size() - 1; z >= 0; z--)

		if ((found_sock_record[z].second != L"Unknown process") &&
			(iph->ip_src_addr == found_sock_record[z].first.dwLocalAddr &&
				iph->ip_dst_addr == found_sock_record[z].first.dwRemoteAddr &&				
				tcph->tcp_dstport == found_sock_record[z].first.dwRemotePort) ||
			(iph->ip_src_addr == found_sock_record[z].first.dwRemoteAddr &&
				iph->ip_dst_addr == found_sock_record[z].first.dwLocalAddr &&
				tcph->tcp_srcport == found_sock_record[z].first.dwRemotePort))			
		{

			// имя процесса будет таким же, как в одном из предыдущих сокетов с такой связкой IP+порт
		    return found_sock_record[z].second;			
		}

	return L"Unknown process";
}



void print_help()
{
	cout << endl << endl;
	cout << "  Order of using options and flags: ";
	cout << "sniffer.exe [-h -D -i <interface number> -v -u -p <process name>] -f <filter expression>\n\n\n";

	cout << "  -h, --help                           Show this help" << endl;
	cout << "  -D, --list-interfaces                Show list of available interfaces" << endl;
	cout << "  -i <interface number>                Interface number to capture (default - 1)" << endl;
	cout << "  -v                                   Short print in single-line format (default - quite mode)" << endl;
	cout << "  -u, --unknown                        Captute only unknown traffic, which unrelated with processes" << endl;
	cout << "  -p, --process-name <process name>    Filtering by process_name (default - no filtering)" << endl;
	cout << "  -f, --filter <expression>            Use expression for winpcap-filter (this argument must be the last)\n\n";
}


char print_ifaces(vector<string> &iface_name, vector<u_long> &iface_ip, int argc, int flag)
{
	pcap_if_t* interfaces, * iface;       // списки для хранения информации о доступных интерфейсах
	char count = '1';                     // номер текущего интерфейса
	string buf_ip;                        // буфер для хранения преобразованного IP (для inet_ntop)
	string errbuf;                        // буфер для хранения сообщения об ошибке

	// Получаем список доступных интерфейсов
	
	if (pcap_findalldevs(&interfaces, &errbuf[0]) == PCAP_ERROR)
		error_exit(1);

	cout << endl << endl;

	if (argc <= 1)
		cout << "Select the interface to capture:" << endl << endl;
	
	for (iface = interfaces; iface != NULL; iface = iface->next)
	{
		for (pcap_addr_t* ip = iface->addresses; ip != NULL; ip = ip->next)
			if (ip->addr->sa_family == AF_INET)
			{
				if (flag != 1)
				{
					iface_name[count - '0'] = iface->name;                                   // сохраняем имена интерфейсов
					iface_ip[count - '0'] = ((sockaddr_in*)ip->addr)->sin_addr.S_un.S_addr;  // сохраняем адреса интерфейсов
				}				
				
				if (argc <= 1 || flag == 1)
				{
					cout << count << ". " << inet_ntop(AF_INET, &((sockaddr_in*)ip->addr)->sin_addr,
						&buf_ip[0], 16) << endl;  // вывод IP-адресов в консоль
				}					

				count++;
			}
	}

	pcap_freealldevs(interfaces);         // очищаем список с ранее полученными интерфейсами

	return count;                         // возвращаем количество сохраненных интерфейсов
}