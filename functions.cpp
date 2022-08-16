#include "sniffer.h"
using namespace std;


WSADATA wsData;
SOCKET s;
wstring previous_name;


void error_exit(int code)
{
	switch (code)
	{
	case 1:  cout << "\nError WinSock version initialization: #" << WSAGetLastError() << endl; break;
	case 2:  cout << "\nError socket initialization: #" << WSAGetLastError() << endl; break;
	case 3:  cout << "\nError get the hostname: #" << GetLastError() << endl; break;
	case 4:  cout << "\nError get the list of IP-adresses: #" << GetLastError() << endl; break;
	case 5:  cout << "\nError socket binding: #" << WSAGetLastError() << endl; break;
	case 6:  cout << "\nError WSAIoctl function: #" << WSAGetLastError() << endl; break;
	case 7:	 cout << "\nError memory allocation: #" << GetLastError() << endl; break;
	case 8:  cout << "\nError GetExtendedTcpTable: #" << GetLastError() << endl; break;
	case 9:  cout << "\nError GetExtendedUdpTable: #" << GetLastError() << endl; break;
	case 10: cout << "\nError create pcap file: #" << GetLastError() << endl; break;
	case 11: cout << "\nError write global header to pcap file: #" << GetLastError() << endl; break;
	case 12: cout << "\nError write packet header to pcap file: #" << GetLastError() << endl; break;
	case 13: cout << "\nError write fakeeth to pcap file: #" << GetLastError() << endl; break;
	case 14: cout << "\nError write packet data to pcap file: #" << GetLastError() << endl; break;
	case 15: cout << "\nError write process name to pcap file: #" << GetLastError() << endl; break;
	}

	closesocket(s);
	WSACleanup();
	cin.get();
	exit(code);
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

	switch (iph->ip_protocol) {
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
	for (int j = 0; j < (ip_len + added); j++) {
		if (j >= ip_len)
			printf("   ");
		else
			if (Buffer[j] <= 15)
				printf("0%X ", Buffer[j]);
			else
				printf("%X ", Buffer[j]);

		if ((j + 1) % 16 == 0 && j != 0) {
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

	if (count == 1) {
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


	if (GetModuleFileNameEx(hProcess, 0, nameProc, MAX_PATH) != NULL) {  // ищем имя процесса по хэндлу
		CloseHandle(hProcess);
		wstring process_name = nameProc;
		size_t pos = process_name.rfind('\\');  // отрезаем лишний путь и берём только имя файла
		if (pos != string::npos) {
			process_name = process_name.substr(pos + 1);
			return process_name;
		}
	}

	CloseHandle(hProcess);
	return L"Unknown process";
}



wstring GetTcpProcessName(IPHeader* iph, TCPHeader* tcph, wstring& enter_procname)         
{
	PMIB_TCPTABLE_OWNER_PID pTcpTable = (MIB_TCPTABLE_OWNER_PID*)malloc(sizeof(MIB_TCPTABLE_OWNER_PID));
	DWORD dwSize = sizeof(MIB_TCPTABLE_OWNER_PID), dwRetVal = 0;
	if ((dwRetVal = GetExtendedTcpTable(pTcpTable, &dwSize, true, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0))
		== ERROR_INSUFFICIENT_BUFFER) {
		free(pTcpTable);
		pTcpTable = (MIB_TCPTABLE_OWNER_PID*)malloc(dwSize);
		if (pTcpTable == NULL) {
			free(pTcpTable);
			error_exit(7);
		}
	}

	wstring process_name;
	if ((dwRetVal = GetExtendedTcpTable(pTcpTable, &dwSize, true, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0))
		== NO_ERROR) {

		for (int i = 0; i < (int)pTcpTable->dwNumEntries; i++)  // ищем связку IP/порт пакета в таблице соединений

			if ((iph->ip_src_addr == pTcpTable->table[i].dwLocalAddr &&
				iph->ip_dst_addr == pTcpTable->table[i].dwRemoteAddr &&
				tcph->tcp_srcport == pTcpTable->table[i].dwLocalPort &&
				tcph->tcp_dstport == pTcpTable->table[i].dwRemotePort) ||
				(iph->ip_src_addr == pTcpTable->table[i].dwRemoteAddr &&
					iph->ip_dst_addr == pTcpTable->table[i].dwLocalAddr &&
					tcph->tcp_srcport == pTcpTable->table[i].dwRemotePort &&
					tcph->tcp_dstport == pTcpTable->table[i].dwLocalPort)) {


				//когда статус TIME_WAIT и PID = 0, handle не открывается, но процесс есть и связан с
				//предыдущим пакетом
				if (pTcpTable->table[i].dwState != 11 && pTcpTable->table[i].dwOwningPid != 0) {
					process_name = GetProcessNameByPID(pTcpTable->table[i].dwOwningPid);
					previous_name = process_name;
				}
				else
					process_name = previous_name;	//имя процесса будет таким же, как в предыдущем пакете			

				if (enter_procname == L"NULL" || enter_procname == process_name) {
					free(pTcpTable);
					return process_name;
				}
			}

		free(pTcpTable);
		return L"NULL";
	}
	else
	{
		free(pTcpTable);
		error_exit(8);
	}
}



wstring GetUdpProcessName(IPHeader* iph, UDPHeader* udph, wstring& enter_procname)
{
	PMIB_UDPTABLE_OWNER_PID pUdpTable = (MIB_UDPTABLE_OWNER_PID*)malloc(sizeof(MIB_UDPTABLE_OWNER_PID));
	DWORD dwSize = sizeof(MIB_UDPTABLE_OWNER_PID), dwRetVal = 0;
	if ((dwRetVal = GetExtendedUdpTable(pUdpTable, &dwSize, true, AF_INET, UDP_TABLE_OWNER_PID, 0))
		== ERROR_INSUFFICIENT_BUFFER) {
		free(pUdpTable);
		pUdpTable = (MIB_UDPTABLE_OWNER_PID*)malloc(dwSize);
		if (pUdpTable == NULL) {
			free(pUdpTable);
			error_exit(7);
		}
	}

	if ((dwRetVal = GetExtendedUdpTable(pUdpTable, &dwSize, true, AF_INET, UDP_TABLE_OWNER_PID, 0))
		== NO_ERROR) {

		for (int i = 0; i < (int)pUdpTable->dwNumEntries; i++)  // ищем связку IP/порт пакета в таблице соединений

			if ((iph->ip_src_addr == pUdpTable->table[i].dwLocalAddr &&
				udph->udp_srcport == pUdpTable->table[i].dwLocalPort) ||
				(iph->ip_dst_addr == pUdpTable->table[i].dwLocalAddr &&
					udph->udp_dstport == pUdpTable->table[i].dwLocalPort)) {

				wstring process_name = GetProcessNameByPID(pUdpTable->table[i].dwOwningPid);
				if (enter_procname == L"NULL" || enter_procname == process_name) {
					free(pUdpTable);
					return process_name;
				}
			}

		free(pUdpTable);
		return L"NULL";
	}
	else
	{
		free(pUdpTable);
		error_exit(9);
	}
}



void init_gen_pcap_header(pcap_hdr* gen_header)  
{
	gen_header->magic_number = 0xa1b2c3d4;
	gen_header->version_major = 2;
	gen_header->version_minor = 4;
	gen_header->thiszone = 0;
	gen_header->sigfigs = 0;
	gen_header->snaplen = 65535+1000;            // взяли с запасом, так как будем записывать ещё имя процесса 
	gen_header->network = 1;                     //ethernet
}



void writehead_to_pcap(HANDLE& hFile)            
{
	pcap_hdr* gen_header;

	wstring filename;
	DWORD bytesWritten;

	SYSTEMTIME lt;
	GetLocalTime(&lt);    // создаём каждый раз уникальное имя pcap-файла из временной отметки
	filename = to_wstring(lt.wYear) + L"-" + to_wstring(lt.wMonth) + L"-" + to_wstring(lt.wDay) + L"-" +
		to_wstring(time(0)) + L".pcap";

	hFile = CreateFileW(filename.c_str(), GENERIC_WRITE, NULL, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile == INVALID_HANDLE_VALUE)
		error_exit(10);

	gen_header = (pcap_hdr*)malloc(sizeof(pcap_hdr));
	memset(gen_header, 0, sizeof(pcap_hdr));
	init_gen_pcap_header(gen_header);

	BOOL write_res = WriteFile(hFile, gen_header, sizeof(pcap_hdr), &bytesWritten, NULL);
	if (write_res == 0)      // записали в pcap-файл глобальный заголовок
		error_exit(11);

	wcout << L"\n\n\n\n" << L"Packets will save to file: " << filename << L"\n\n";
	free(gen_header);
}



void writepack_to_pcap(HANDLE& hFile, vector<BYTE> Data, UINT16 data_len, wstring& process_name)            
{
	pcappack_hdr* packHeader;
	DWORD numWritten;	
	BOOL write_res;

	//заглушка канального уровня для wireshark
	BYTE fakeeth[14] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x08,0x00 };	

	packHeader = (pcappack_hdr*)malloc(sizeof(pcappack_hdr));
	memset(packHeader, 0, sizeof(pcappack_hdr));

	//получаем временные отметки для каждого пакета
	chrono::system_clock::duration dur = chrono::system_clock::now().time_since_epoch();
	chrono::seconds sec = chrono::duration_cast<chrono::seconds>(dur);

	//заполняем pcap-структуру заголовка каждого пакета
	packHeader->ts_sec = sec.count();
	packHeader->ts_usec = chrono::duration_cast<chrono::microseconds>(dur-sec).count();
	packHeader->incl_len = (UINT32)data_len + sizeof(fakeeth) + 2 * (process_name.size());
	packHeader->orig_len = (UINT32)data_len + sizeof(fakeeth) + 2 * (process_name.size());

	//запись заголовка пакета для формата pcap
	write_res = WriteFile(hFile, packHeader, sizeof(pcappack_hdr), &numWritten, NULL);
	if (write_res == 0)
		error_exit(12);

	//запись заглушки для wireshark
	WriteFile(hFile, fakeeth, sizeof(fakeeth), &numWritten, NULL);
	if (write_res == 0)
		error_exit(13);

	//запись захваченного пакета
	WriteFile(hFile, &Data[0], (UINT32)data_len, &numWritten, NULL);
	if (write_res == 0)
		error_exit(14);

	//запись имени процесса
	WriteFile(hFile, process_name.c_str(), 2 * (process_name.size()), &numWritten, NULL);
	if (write_res == 0)
		error_exit(15);

	free(packHeader);
}



int isDNS(TCPHeader* tcph, UDPHeader* udph)
{
	if ((tcph != NULL && ntohs(tcph->tcp_dstport) == 53) || (udph != NULL && ntohs(udph->udp_dstport) == 53))
		return 0;      //dns-запрос
	else
		if ((tcph != NULL && ntohs(tcph->tcp_srcport) == 53) || (udph != NULL && ntohs(udph->udp_srcport) == 53))
			return 1;  //dns-ответ
		else
			return 2;  //не dns-пакет
}