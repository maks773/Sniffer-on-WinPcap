#include "sniffer.h"
using namespace std;


int capture_packets = 0;                       // ������� ������ ���������� ����������� �������
int saved_packets = 0;                         // ������� ���������� ����������� � ���� �������

vector<pcap_pkthdr> AllHeaders;                // ��� �������� pcap-���������� ����������� �������
vector<vector<u_char>> AllPackets;             // ��� �������� ����������� ������������ �������

int thread_flag = 0;                           // ���� ��������� ������ (1 - �������, 0 - �� �������)
int close_flag = 0;                            // ���� ��������� _kbhit (���� ��������� ������� ��� ���)

wstring enter_procname = L"NULL";              // ��� �������� ���������� � ������� ����� ��������
char num = '2';                                // ��� �������� ���������� ������ ��� ���������� ������
pcap_t* handle;                                // ����� ���������� ��� �������
mutex m;                                       // ������� ��� ������������� �������
u_long ip_dev;                                 // ��� �������� IP-������ ���������� ���������� �������


void threadFunction2()
{
	while (1)                                  // ������� ��������� ������� �������������
	{
		if (_kbhit())
		{
			pcap_breakloop(handle);            // ��������� ������ ����� �������
			close_flag = 1;		               // ������������� ���� ���������� ������ ���������
			return;
		}
	}
}


void threadFunction(u_char* file, vector<pcap_pkthdr>& AllHeaders, vector<vector<u_char>>& AllPackets)
{	
	int dns_flag = 2;                // ����-������������� dns-������ 
	int t = 0;                       // ������� DNS-�������
	int syn_flag = 0;                // ������� TCPsyn-�������
	vector<int> dns_numbers;         // ��� �������� ������� DNS-�������
	vector<temp_buf> Temp(65535);    // ��� �������� ����������� DNS-�������
	
	for (int i = 0; ; i++)           // �������� ������ ������� ������������ ������
	{	
		while (i >= capture_packets)             
		{
			if (close_flag == 1)                  // ���� ���������������� ��� ����������� ������ � ��� ����� <enter>,
			{                                     // �� ��������� ������ ���������
				print_summary(capture_packets, saved_packets);   // ������ �������� ���������� ����� �������
				return;                    
			}				                      // ���� ���������������� ��� ������, � ����� ��� �� ���� ���������,
			else                                  // �� ���������������� �����, ����� �� ���������� ����, �.�.
				this_thread::sleep_for(chrono::milliseconds(1)); // ��� ������� <enter> ���� ����������� ����� �������
		}
		
		m.lock();

		pcap_pkthdr AllHeaders_item = AllHeaders[i];       // ��������� pcap-��������� ������
		vector<u_char> AllPackets_item = AllPackets[i];	   // ��������� ���������� ������

		m.unlock();

		// ��� �������� ���������� IP, TCP, UDP
		IPHeader* iph = NULL;  TCPHeader* tcph = NULL;  UDPHeader* udph = NULL;

		wstring process_name = L"Unknown process";             // ��� �������� ����� ��������
		wstring dns_proc_name = L"Unknown process";            // ��� �������� ����� �������� dns-������ 

		iph = (IPHeader*)(&AllPackets_item[0] + 14);           // �������� ��������� IP
		UINT ip_hlen = (UINT)((iph->ip_ver_hlen & 15) * 4);    // ����� IP-���������
		
		if (iph->ip_protocol == IPPROTO_TCP)
		{
			tcph = (TCPHeader*)(&AllPackets_item[0] + 14 + ip_hlen);      // �������� ��������� TCP
			process_name = GetTcpProcessName(iph, tcph, enter_procname);  // ���� ����� ������ � ��������� � ��
		}
		else if (iph->ip_protocol == IPPROTO_UDP)
		{
			udph = (UDPHeader*)(&AllPackets_item[0] + 14 + ip_hlen);      // �������� ��������� UDP
			process_name = GetUdpProcessName(iph, udph, enter_procname);  // ���� ����� ������ � ��������� � ��
		}
		else
			continue;    // ���� ��� �� ����� TCP ��� UDP, �� ��������� � ������� ���������� ������
		
		int is_dns = isDNS(tcph, udph);      // ��������, ��������� ����� � DNS (0,1) ��� ��� (2)  

		if (is_dns != 2)                     
		{
			dns_numbers.push_back(i);        // ���������� ����� ������� DNS-������
			
			Temp[t].ipheader = *iph;		 // ���������� ��� ��������� IP	

			if (udph != NULL)
				Temp[t].udpheader = *udph;   // ���������� ��� ��������� UDP
			else if (tcph != NULL)
				Temp[t].tcpheader = *tcph;   // TCP ����������� ��� DNS, �� �� ������ ������ ����� �����

			t++;			                 // �������� �������� ����������� DNS-�������

			if (is_dns == 0)
				dns_flag = 0;                // DNS-������
			else
				dns_flag = 1;                // DNS-�����
		}
		
		if (dns_flag == 1 && isTCPSyn(tcph))      // ���� ������ ����� TCP-syn ����� DNS-������
		{
			string buf_ip;                   // ����� ��� �������� IP-������ (��� ������� inet_ntop)			
			string temp;                     // ������ ����� IP-������ � ���� ������
			vector<int> temp_ip(4, 0);       // ������ IP-����� � ���� ������ �����
			int j = 0;                       // ����������-������� ��� ������

			// ����������� IP-����� � ������
			inet_ntop(AF_INET, &iph->ip_dst_addr, &buf_ip[0], 16);

			stringstream stream(buf_ip);
			while (getline(stream, temp, '.'))
			{
				temp_ip[j] = stoi(temp);     // ������� IP-������ ��������� � ������ ������� �� ������ �����
				j++;
			}

			for (int z = dns_numbers.size() - 1; z >= 0; z--)
			{
				// ������� ����������� DNS-������ � ������ ����� �������� (int)

				vector<int> int_pack(AllPackets[dns_numbers[z]].size());  	

				for (j = 0; j < int_pack.size(); j++)
					int_pack[j] = AllPackets[dns_numbers[z]][j];

				// ����� IP ������ ��������� TCP-syn ������ � DNS-������ (��� ��� ����� DNS-������
				// ��� ����� TCP c ���������� ���������� �� ������ �� ���������� �������)

				auto it = search(int_pack.begin(), int_pack.end(), temp_ip.begin(), temp_ip.end());

				if (it != int_pack.end())          // ���� IP ������� ������, �� ����������� DNS-������ �������
				{                                  // � ��������� ����� TCP-������
					dns_proc_name = process_name;
					syn_flag = 5;
					break;
				}			
			}

			if (syn_flag != 5)  // ��������������, ��� IP �� DNS-������ �������� IP-������� ���������� ���������   
				syn_flag++;     // 5-� TCPsyn-������� (���� ���, �� ������� ����� dns-������ ��� unknown process)

			if (syn_flag >= 5)
			{
				if (enter_procname == L"NULL" || enter_procname == dns_proc_name)

					for (j = 0; j < dns_numbers.size(); j++)    // ������� ����������� DNS-������
					{
						saved_packets++;         // ����������� ������� ����������� �������

						if (num == '1')          // ������� ����� � �������
							print_info(saved_packets, &Temp[j].ipheader, &Temp[j].tcpheader,
								&Temp[j].udpheader, dns_proc_name);

						wstring dns_proc_name1 = L"prc_name:" + dns_proc_name;  // ��������� ��� ���������� Wireshark

						m.lock();

						// ����������� ��� ������� �������������� ������
						AllPackets[dns_numbers[j]].reserve(65535 + 1000);

						// ��������� � ����� ������ ��� ��������
						AllPackets[dns_numbers[j]].insert(AllPackets[dns_numbers[j]].begin()
							+ AllHeaders[dns_numbers[j]].caplen, dns_proc_name1.begin(), dns_proc_name1.end());

						// ������������ ����� ������ � pcap-���������
						AllHeaders[dns_numbers[j]].caplen = AllHeaders[dns_numbers[j]].caplen + dns_proc_name1.size();
						AllHeaders[dns_numbers[j]].len = AllHeaders[dns_numbers[j]].caplen;

						// ���������� ����� � ����
						pcap_dump(file, &AllHeaders[dns_numbers[j]], &AllPackets[dns_numbers[j]][0]);

						m.unlock();
					}

			    dns_numbers.clear();  // ������� ������ � �������� DNS-�������
			    dns_flag = 2;         // ������������� ���� � ��������� ���������
			    t = 0;                // �������� ������� DNS-�������
				syn_flag = 0;         // �������� ������� TCPsyn-�������
			}
		}
		else if (is_dns != 2) continue;  // ���� ����� DNS-������ ���� ����� ������ DNS-������, � �� TCP-syn, ��
		                                 // ��������� � �� ������� (����������) 


		// ���� ����� �� DNS, �� ����� ������� ���, ��� ��� ��� �������� ��� ���� ������������ � ���� �� ��������

		if ((enter_procname == L"NULL" || enter_procname == process_name) && process_name != L"Reject")
		{
			saved_packets++;             

			if (num == '1')              
				print_info(saved_packets, iph, tcph, udph, process_name);

			process_name = L"prc_name:" + process_name;  // �c������� ��������� ��� ���������� Wireshark

			AllPackets_item.reserve(65535 + 1000);

			AllPackets_item.insert(AllPackets_item.begin() + AllHeaders_item.caplen,
				process_name.begin(), process_name.end());

			AllHeaders_item.caplen = AllHeaders_item.caplen + process_name.size();

			AllHeaders_item.len = AllHeaders_item.caplen;

			pcap_dump(file, &AllHeaders_item, &AllPackets_item[0]);			
		}		
	}
}


void process_packet(u_char* file, const struct pcap_pkthdr* header, const u_char* Buffer)
{    
	if (Buffer != NULL && header != NULL /* && header->len == header->caplen*/)
	{
		vector<u_char> temp_buf(Buffer, Buffer + header->caplen);  // ����������� ��������� ������������ ������ � ������
		
		m.lock();

		AllPackets.push_back(temp_buf);                            // ��������� ������ ����������� �����
		AllHeaders.push_back(*header);                             // ��������� ������ ����������� pcap-��������� ������  
		capture_packets++;		                                   // ����������� ������� ����������� �������	

		m.unlock();

		if (thread_flag != 1)                                      // ��������� ����� ��� ������� �������
		{                                                          
			thread_flag = 1;
			thread thr(threadFunction, file, ref(AllHeaders), ref(AllPackets));
			SetThreadPriority(thr.native_handle(), 2);             // �������� ��������� ������
			thr.detach();                                          // ����� �������� ����������� (����� �� "�������")
		}
	}
}


int main(int argc, char *argv[])
{
	string errbuf;                       // ����� ��� �������� ��������� �� ������
	vector<string> iface_name(100);      // ����� ��� �������� ��� �����������
	vector<u_long> iface_ip(100);        // ����� ��� �������� ������� ����������� 
	char count = '1';                    // ���������� ��������� ��� ������� �����������
	char iface_num = '1';                // ����� ���������� ���������� (1 - �� ���������)	
	string wpcap_filter = "";            // ����� ��� �������� ��������� winpcap �������
	int filter_flag = 0;                 // ���� (1 - � ������� ���� �������� ��� winpcap �������)
	bpf_program fp;                      // ���������������� winpcap-������


	if (argc > 1)                        // ������ ���������� ��������� ������
	{
		int arg_flag = 0;                // ���� (1 - ��������, ��������� ����� ������)
		
		for (int i = 0; i < argc; i++)
		{
			if (filter_flag == 1)        // c�������� ��������� ������� ����� ��������� -f
			{
				wpcap_filter = wpcap_filter + string(argv[i]) + " ";
				continue;
			}
			
			if (string(argv[i]) == "--help" || string(argv[i]) == "-h")
			{
				print_help();            // ����� help
				exit(0);
			} else

			if (string(argv[i]) == "--list-interfaces" || string(argv[i]) == "-D")
			{
				print_ifaces(iface_name, iface_ip, argc, 1);   // ����� ������ ��������� ��� ������� �����������
				exit(0);
			} else				

			if (string(argv[i]) == "-i" && i < argc - 1)       // ��������� ����� ���������� ��� �������
			{
				iface_num = argv[i+1][0];
				arg_flag = 1;
			} else	
			 
			if (string(argv[i]) == "-v")                       // ����� ������ � ������� ������� � �������
			{
				num = '1';
				arg_flag = 0;
			} else		

			if (string(argv[i]) == "-u" || string(argv[i]) == "--unknown") 
			{
				enter_procname = L"Unknown process";           // ��� ������� ������������� �� ��������� �������
				arg_flag = 0;
			} else				

			if ((string(argv[i]) == "-p" || string(argv[i]) == "--process-name") && i < argc - 1)
			{
				string temp(argv[i + 1]);                      // ��������� ��� �������� ��� ����������
				wstring temp1(temp.begin(), temp.end());
				enter_procname = temp1;
				arg_flag = 1;
			} else

			if ((string(argv[i]) == "-f" || string(argv[i]) == "--filter") && i < argc - 1)  // ������� winpcap
			{
				filter_flag = 1;
				arg_flag = 1;
			} else

			if (argv[i][0] == '-' || (argv[i][0] != '-' && (arg_flag == 0 || arg_flag > 1) && i > 0))
				error_exit(10);                    
			else                                    // ��������� �� ������, ���� �������� �������� �����������
				arg_flag = 2;
		}
	}


	// ���������� �/��� ����� ������� IP-������� � ������� (� ���������� ������)

	count = print_ifaces(iface_name, iface_ip, argc, 0);  


	// ����������� ��� ������� ��������� � ���������� ������ (�� ������ �� ����)
	
	if (argc <= 1)
	{
		cout << endl << "Please, enter the number of interface: ";

		// ����� ���������� � �������

		do
		{
			iface_num = _getche();
		} while (iface_num >= count || iface_num < '1');
	}


	// ��������� ����� ��� ������� ������� � ���������� ����������

	handle = pcap_open_live(iface_name[iface_num - '0'].c_str(), 65535, 1, 1, &errbuf[0]);
	if (handle == NULL)
		error_exit(2);

	ip_dev = iface_ip[iface_num - '0'];             // ��������� IP-����� ���������� ����������


	// ����������� ��� ������� ��������� � ���������� ������ (�� ������ �� ����)
	
	if (argc <= 1)
	{
		cout << "\n\n\n\n" << "Use process filtering? (y/n): ";

		do
		{
			num = _getche();
		} while (num != 'y' && num != 'n');             // ������ ������� �� ������������ �������� (y) ��� ��� (n)

		if (num == 'y')
		{
			cout << endl << endl << "Please, enter name of the process (for example, chrome.exe)";
			cout << endl << "or if you want to capture all non-process related traffic, type Unknown process: ";
			getline(wcin, enter_procname);		        // ���� (y), ��������� � ������� ��� ��������
		}                                               // ��� ������ ���� ����-�-����, ��� � ������ netstat
														// ��� ������� �������, �� ���������� � ����������, ����������
														// ������ ������ Unknown process


		cout << "\n\n\n\n" << "Use winpcap-filters? (y/n): ";

		do
		{
			num = _getche();
		} while (num != 'y' && num != 'n');             // ����� ���� ��������� winpcap-������� (y) ��� ��� (n)

		if (num == 'y')
		{
			cout << endl << endl << "Please, enter expression of winpcap captute filter (for example, port 80): ";			
			getline(cin, wpcap_filter);
			filter_flag = 1;
		}
	}


	if (filter_flag == 1)
	{
		if (pcap_compile(handle, &fp, wpcap_filter.c_str(), 0, ip_dev) == -1)  // ����������� winpcap-������
			error_exit(8);

		if (pcap_setfilter(handle, &fp) == -1)                                 // ������������� winpcap-������
			error_exit(9);
	}


	HANDLE hInput = GetStdHandle(STD_INPUT_HANDLE);    // ��������� ����� �������� �������������� � �������
	DWORD prevConsoleMode;
	GetConsoleMode(hInput, &prevConsoleMode);
	SetConsoleMode(hInput, prevConsoleMode & ENABLE_EXTENDED_FLAGS);

	
	// ����������� ��� ������� ��������� � ���������� ������ (�� ������ �� ����)
	
	if (argc <= 1)
	{
		cout << "\n\n\n\n" << "1. Short print in single-line format" << endl;
		cout << "2. Quiet mode. Only write to pcap file" << endl << endl;
		cout << "Please, select the mode: ";

		do                                          // ����� ������ ������ ���������
		{
			num = _getche();
		} while (num != '1' && num != '2');
	}


	string filename;                                // ��� �������� ����� pcap-�����
	SYSTEMTIME lt;                                  // ��� �������� ��������� �������

	GetLocalTime(&lt);                              // �������� ��������� ������� ��� ����� pcap-�����

	filename = to_string(lt.wYear) + "-" + to_string(lt.wMonth) + "-" + to_string(lt.wDay) + "-" +
		to_string(time(0)) + ".pcap";               // ������� ��� �����

	pcap_dumper_t* file = pcap_dump_open(handle, filename.c_str());     // ������� pcap-���� ��� ������ �������
	if (file == NULL)
		error_exit(3);


	thread thr2(threadFunction2);       // ��������� �����, ������� ����������� ��������� ������� �������������

	thr2.detach();                      // ����� �������� �����������

	
	cout << "\n\n\n\n" << "Start packet capture...  [ TO STOP capture PRESS <ENTER> ]" << "\n\n";
	
	if (PCAP_ERROR == pcap_loop(handle, -1, process_packet, (unsigned char*)file))    // �������� ������ �������
		error_exit(7);


	if (capture_packets == 0)                               // ������� ����������, ���� �� ��� �������� �� ���� �����
		print_summary(capture_packets, saved_packets);

	pcap_close(handle);                                     // ��������� �����

	SetConsoleMode(hInput, prevConsoleMode);                // ������� ������� �������� �������	
	
	while (true) cin.get();
	
	return 0;
}