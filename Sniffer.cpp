#include "sniffer.h"
using namespace std;


int p_count = 0;                                    // ������� ���������� ���������� �������
vector<temp_buf> Temp(65535);                       // ��� �������� ����������� ������� ����� DNS-�������� � �������
vector<vector<u_char>> Buf(65535);                  // ��� �������� ���������� ������� ����� DNS-�������� � �������
int t = 0;                                          // ������� ������� ����� DNS-�������� � �������
int flag = 100;                                     // 100 - ��������� ��������� �����
wstring enter_procname = L"NULL";                   // ��������� ��� ��������
char num;                                           // �������� ��������� ������ � ������ �������
pcap_t* handle;                                     // ����� ���������� ��� �������


void process_packet(u_char* file, const struct pcap_pkthdr* header, const u_char* Buffer)
{
	IPHeader* iph = NULL;  TCPHeader* tcph = NULL;  UDPHeader* udph = NULL;
	wstring process_name = L"Unknown process";             // ��� �������� ����� ��������

	iph = (IPHeader*)(Buffer + 14);                        // �������� ��������� IP
	UINT ip_hlen = (UINT)((iph->ip_ver_hlen & 15) * 4);    // ����� IP-���������

	if (iph->ip_protocol == IPPROTO_TCP)
	{
		tcph = (TCPHeader*)(Buffer + 14 + ip_hlen);                   // �������� ��������� TCP
		process_name = GetTcpProcessName(iph, tcph, enter_procname);  // ���� ����� ������ � ��������� � ��
	}
	else if (iph->ip_protocol == IPPROTO_UDP)
	{
		udph = (UDPHeader*)(Buffer + 14 + ip_hlen);                   // �������� ��������� UDP
		process_name = GetUdpProcessName(iph, udph, enter_procname);  // ���� ����� ������ � ��������� � �� 
	}
	else
		return;
		
	int is_dns = isDNS(tcph, udph);                        // ��������, ��������� ����� � DNS (0,1) ��� ��� (2)               

	if (is_dns == 2 && flag == 1)                          // ��������� ������, ������� ����� dns-������
	{                      
		string buf_ip(16, '\0');  vector<int> temp_ip(4, 0);  int nn = 0;  string temp;
		inet_ntop(AF_INET, &iph->ip_dst_addr, (char*)buf_ip.c_str(), 16);
		stringstream stream(buf_ip);

		while (getline(stream, temp, '.'))
		{
			temp_ip[nn] = stoi(temp);    // ������� IP-������ ��������� � ������ ������� �� ������ �����
			nn++;
		}

		vector<int> int_pack(65535);	 // ������� ������ � ������ ����� �������� (int)		
		for (nn = 0; nn < 65535; nn++)
			int_pack[nn] = Buf[t - 1][nn];

		// ����� IP ������ ��������� TCP ������ � DNS-������ (��� ��� ����� DNS-������
		// ��� ����� TCP c ���������� ���������� �� ������ �� ���������� �������)

		auto it = search(int_pack.begin(), int_pack.end(), temp_ip.begin(), temp_ip.end());

		if (it != int_pack.end() && process_name != L"NULL") 
		{
			for (int i = 0; i < t; i++)
			{                                 // ���� ����� ������ � TCP-����� ������ � ���������, �� �������
				p_count++;                    // ����������� DNS-�����, ������ � ������ ����� ����,
											  // ��� ��� DNS-������ ���� ������� � ���� ���������
				if (num == '1')
					print_info(p_count, &Temp[i].ipheader, &Temp[i].tcpheader,
						&Temp[i].udpheader, process_name);								
				
				Buf[i].insert(Buf[i].begin() + Temp[i].header.len, process_name.begin(), process_name.end());				
				Temp[i].header.len = Temp[i].header.len + process_name.size();
				Temp[i].header.caplen = Temp[i].header.len;

				pcap_dump(file, &Temp[i].header, (u_char*)&Buf[i][0]);				
			}
			t = 0; flag = 100;                // �������� ������� � ������ ���� � ��������� ���������
		}
		else
		{
			t = 0; flag = 100; return;
		}					
	}

	if (is_dns != 2 || flag != 100)           // ��������� ������ ����� DNS-�������� � DNS-�������
	{	 
		Temp[t].ipheader = *iph;
		Temp[t].header = *header;

		if (udph != NULL)
			Temp[t].udpheader = *udph;
		else
			Temp[t].tcpheader = *tcph;

		vector<u_char> temp_vec(Buffer, Buffer + 65535 + 1000);
		Buf[t] = temp_vec;  t++;

		if (is_dns == 0)                    // DNS-������
			flag = 0;
		else if (is_dns == 1)               // DNS-�����
			flag = 1;

		return;
	}


	if (process_name != L"NULL")            // ���� ����������� ����� ������ � ���������, ������� ���
	{     
		p_count++;

		if (num == '1')
			print_info(p_count, iph, tcph, udph, process_name);		
			
		vector<u_char> temp_vec(Buffer, Buffer + 65535 + 1000);			
		temp_vec.insert(temp_vec.begin() + header->len, process_name.begin(), process_name.end());		
		Temp[0].header = *header;
		Temp[0].header.len = header->len + process_name.size();
		Temp[0].header.caplen = Temp[0].header.len;

		pcap_dump(file, &Temp[0].header, (u_char*)&temp_vec[0]);		
	}

	if (_kbhit()) pcap_breakloop(handle);   // ��������� ������� �� ������� ����� ������� � ������� 
}


int main()
{
	pcap_if_t *interfaces, *iface;       // ������ ��� �������� ���������� � ��������� �����������
	string errbuf;                       // ����� ��� �������� ��������� �� ������
	
	// �������� ������ ��������� �����������

	if (pcap_findalldevs(&interfaces, &errbuf[0]) == PCAP_ERROR)
		error_exit(1);

	vector<string> iface_name(100);      // ����� ��� �������� ��� �����������
	char count = '1';                    // ����� �������� ����������
	string buf_ip;                       // ����� ��� �������� ���������������� IP (��� inet_ntop)

	cout << "Select the interface to capture:" << endl << endl;

	// ����� ������� IP-������� � �������

	for (iface = interfaces; iface != NULL; iface = iface->next)
	{
		for (pcap_addr_t *ip = iface->addresses; ip != NULL; ip = ip->next)
			if (ip->addr->sa_family == AF_INET)
			{
				iface_name[count - '0'] = iface->name;      // ��������� ����� �����������

				cout << count << ". " << inet_ntop(AF_INET, &((sockaddr_in*)ip->addr)->sin_addr,
					&buf_ip[0], 16) << endl;

				count++;
			}			
	}

	cout << endl << "Please, enter the number of interface: ";

	// ����� ���������� � �������

	do                              
	{
		num = _getche();
	} while (num >= count || num < '1');

	// ��������� ����� ��� ������� ������� � ���������� ����������

	handle = pcap_open_live(iface_name[num - '0'].c_str(), 65535 + 1000, 1, 0, &errbuf[0]);
	if (handle == NULL)
		error_exit(2);

	pcap_freealldevs(interfaces);                   // ������� ������ � ����� ����������� ������������

	cout << "\n\n\n\n" << "Use process filtering? (y/n): ";

	do
	{
		num = _getche();
	} while (num != 'y' && num != 'n');             // ������ ������� �� ������������ �������� (y) ��� ��� (n)

	if (num == 'y') {
		cout << endl << endl << "Please, enter name of the process (for example, chrome.exe)";
		cout << endl << "or if you want to capture all non-process related traffic, type Unknown process: ";
		getline(wcin, enter_procname);		        // ���� (y), ��������� � ������� ��� ��������
	}                                               // ��� ������ ���� ����-�-����, ��� � ������ netstat
	                                                // ��� ������� �������, �� ���������� � ����������, ����������
	                                                // ������ ������ Unknown process

	HANDLE hInput = GetStdHandle(STD_INPUT_HANDLE); // ��������� ����� �������� �������������� � �������
	DWORD prevConsoleMode;
	GetConsoleMode(hInput, &prevConsoleMode);
	SetConsoleMode(hInput, prevConsoleMode & ENABLE_EXTENDED_FLAGS);
	
	cout << "\n\n\n\n" << "1. Short print in single-line format" << endl;	
	cout << "2. Quiet mode. Only write to pcap file" << endl << endl;
	cout << "Please, select the mode: ";

	do                                              // ����� ������ ������ ���������
	{
		num = _getche();
	} while (num != '1' && num != '2');

	string filename;                                // ��� �������� ����� pcap-�����
	SYSTEMTIME lt;                                  // ��� �������� ��������� �������

	GetLocalTime(&lt);                              // �������� ��������� ������� ��� ����� pcap-�����

	filename = to_string(lt.wYear) + "-" + to_string(lt.wMonth) + "-" + to_string(lt.wDay) + "-" +
		to_string(time(0)) + ".pcap";               // ������� ��� �����

	pcap_dumper_t* file = pcap_dump_open(handle, filename.c_str());     // ������� pcap-���� ��� ������ �������
	if (file == NULL)
		error_exit(3);

	cout << "\n\n\n\n" << "Start packet capture...  [ TO STOP capture PRESS ANY KEY ]" << "\n\n";	
	
	pcap_loop(handle, 0, process_packet, (unsigned char*)file);   // �������� ������ �������

	pcap_close(handle);

	cout << "\n\nPacket capture completed!\n\n";

	SetConsoleMode(hInput, prevConsoleMode);                      // ������� ������� �������� �������
	
	while (true) cin.get();
	
	return 0;
}