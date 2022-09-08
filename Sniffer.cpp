#include "sniffer.h"
using namespace std;


int p_count = 0;                                    // счётчик количества записанных пакетов
vector<temp_buf> Temp(65535);                       // для хранения содержимого пакетов между DNS-запросом и ответом
vector<vector<u_char>> Buf(65535);                  // для хранения заголовком пакетов между DNS-запросом и ответом
int t = 0;                                          // счётчик пакетов между DNS-запросом и ответом
int flag = 100;                                     // 100 - начальное состояние флага
wstring enter_procname = L"NULL";                   // введенное имя процесса
char num;                                           // хранение введеного номера в режиме диалога
pcap_t* handle;                                     // хэндл интерфейса для захвата


void process_packet(u_char* file, const struct pcap_pkthdr* header, const u_char* Buffer)
{
	IPHeader* iph = NULL;  TCPHeader* tcph = NULL;  UDPHeader* udph = NULL;
	wstring process_name = L"Unknown process";             // для хранения имени процесса

	iph = (IPHeader*)(Buffer + 14);                        // выделяем заголовок IP
	UINT ip_hlen = (UINT)((iph->ip_ver_hlen & 15) * 4);    // длина IP-заголовка

	if (iph->ip_protocol == IPPROTO_TCP)
	{
		tcph = (TCPHeader*)(Buffer + 14 + ip_hlen);                   // выделяем заголовок TCP
		process_name = GetTcpProcessName(iph, tcph, enter_procname);  // ищем связь пакета с процессом в ОС
	}
	else if (iph->ip_protocol == IPPROTO_UDP)
	{
		udph = (UDPHeader*)(Buffer + 14 + ip_hlen);                   // выделяем заголовок UDP
		process_name = GetUdpProcessName(iph, udph, enter_procname);  // ищем связь пакета с процессом в ОС 
	}
	else
		return;
		
	int is_dns = isDNS(tcph, udph);                        // проверка, относится пакет к DNS (0,1) или нет (2)               

	if (is_dns == 2 && flag == 1)                          // обработка пакета, идущего после dns-ответа
	{                      
		string buf_ip(16, '\0');  vector<int> temp_ip(4, 0);  int nn = 0;  string temp;
		inet_ntop(AF_INET, &iph->ip_dst_addr, (char*)buf_ip.c_str(), 16);
		stringstream stream(buf_ip);

		while (getline(stream, temp, '.'))
		{
			temp_ip[nn] = stoi(temp);    // перевод IP-адреса назначния в формат массива из четырёх чисел
			nn++;
		}

		vector<int> int_pack(65535);	 // перевод пакета в формат кодов символов (int)		
		for (nn = 0; nn < 65535; nn++)
			int_pack[nn] = Buf[t - 1][nn];

		// поиск IP адреса назначния TCP пакета в DNS-ответе (так как после DNS-ответа
		// идёт пакет TCP c установкой соединения по одному из полученных адресов)

		auto it = search(int_pack.begin(), int_pack.end(), temp_ip.begin(), temp_ip.end());

		if (it != int_pack.end() && process_name != L"NULL") 
		{
			for (int i = 0; i < t; i++)
			{                                 // если адрес найден и TCP-пакет связан с процессом, то выводим
				p_count++;                    // захваченные DNS-ответ, запрос и пакеты между ними,
											  // так как DNS-пакеты тоже связаны с этим процессом
				if (num == '1')
					print_info(p_count, &Temp[i].ipheader, &Temp[i].tcpheader,
						&Temp[i].udpheader, process_name);								
				
				Buf[i].insert(Buf[i].begin() + Temp[i].header.len, process_name.begin(), process_name.end());				
				Temp[i].header.len = Temp[i].header.len + process_name.size();
				Temp[i].header.caplen = Temp[i].header.len;

				pcap_dump(file, &Temp[i].header, (u_char*)&Buf[i][0]);				
			}
			t = 0; flag = 100;                // обнуляем счётчик и ставим флаг в начальное состояние
		}
		else
		{
			t = 0; flag = 100; return;
		}					
	}

	if (is_dns != 2 || flag != 100)           // сохраняем пакеты между DNS-запросом и DNS-ответом
	{	 
		Temp[t].ipheader = *iph;
		Temp[t].header = *header;

		if (udph != NULL)
			Temp[t].udpheader = *udph;
		else
			Temp[t].tcpheader = *tcph;

		vector<u_char> temp_vec(Buffer, Buffer + 65535 + 1000);
		Buf[t] = temp_vec;  t++;

		if (is_dns == 0)                    // DNS-запрос
			flag = 0;
		else if (is_dns == 1)               // DNS-ответ
			flag = 1;

		return;
	}


	if (process_name != L"NULL")            // если захваченный пакет связан с процессом, выводим его
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

	if (_kbhit()) pcap_breakloop(handle);   // остановка захвата по нажатию любой клавиши в консоли 
}


int main()
{
	pcap_if_t *interfaces, *iface;       // списки для хранения информации о доступных интерфейсах
	string errbuf;                       // буфер для хранения сообщения об ошибке
	
	// Получаем список доступных интерфейсов

	if (pcap_findalldevs(&interfaces, &errbuf[0]) == PCAP_ERROR)
		error_exit(1);

	vector<string> iface_name(100);      // буфер для хранения имён интерфейсов
	char count = '1';                    // номер текущего интерфейса
	string buf_ip;                       // буфер для хранения преобразованного IP (для inet_ntop)

	cout << "Select the interface to capture:" << endl << endl;

	// Вывод перечня IP-адресов в консоль

	for (iface = interfaces; iface != NULL; iface = iface->next)
	{
		for (pcap_addr_t *ip = iface->addresses; ip != NULL; ip = ip->next)
			if (ip->addr->sa_family == AF_INET)
			{
				iface_name[count - '0'] = iface->name;      // сохраняем имена интерфейсов

				cout << count << ". " << inet_ntop(AF_INET, &((sockaddr_in*)ip->addr)->sin_addr,
					&buf_ip[0], 16) << endl;

				count++;
			}			
	}

	cout << endl << "Please, enter the number of interface: ";

	// выбор интерфейса в консоли

	do                              
	{
		num = _getche();
	} while (num >= count || num < '1');

	// открываем хэндл для захвата пакетов с выбранного интерфейса

	handle = pcap_open_live(iface_name[num - '0'].c_str(), 65535 + 1000, 1, 0, &errbuf[0]);
	if (handle == NULL)
		error_exit(2);

	pcap_freealldevs(interfaces);                   // очищаем список с ранее полученными интерфейсами

	cout << "\n\n\n\n" << "Use process filtering? (y/n): ";

	do
	{
		num = _getche();
	} while (num != 'y' && num != 'n');             // захват пакетов по определённому процессу (y) или нет (n)

	if (num == 'y') {
		cout << endl << endl << "Please, enter name of the process (for example, chrome.exe)";
		cout << endl << "or if you want to capture all non-process related traffic, type Unknown process: ";
		getline(wcin, enter_procname);		        // если (y), считываем с консоли имя процесса
	}                                               // оно должно быть точь-в-точь, как в выводе netstat
	                                                // для захвата трафика, не связанного с процессами, необходимо
	                                                // ввести строку Unknown process

	HANDLE hInput = GetStdHandle(STD_INPUT_HANDLE); // отключаем режим быстрого редактирования в консоли
	DWORD prevConsoleMode;
	GetConsoleMode(hInput, &prevConsoleMode);
	SetConsoleMode(hInput, prevConsoleMode & ENABLE_EXTENDED_FLAGS);
	
	cout << "\n\n\n\n" << "1. Short print in single-line format" << endl;	
	cout << "2. Quiet mode. Only write to pcap file" << endl << endl;
	cout << "Please, select the mode: ";

	do                                              // выбор режима работы программы
	{
		num = _getche();
	} while (num != '1' && num != '2');

	string filename;                                // для хранения имени pcap-файла
	SYSTEMTIME lt;                                  // для хранения временной отметки

	GetLocalTime(&lt);                              // получаем временную отметку для имени pcap-файла

	filename = to_string(lt.wYear) + "-" + to_string(lt.wMonth) + "-" + to_string(lt.wDay) + "-" +
		to_string(time(0)) + ".pcap";               // создали имя файла

	pcap_dumper_t* file = pcap_dump_open(handle, filename.c_str());     // создаем pcap-файл для записи пакетов
	if (file == NULL)
		error_exit(3);

	cout << "\n\n\n\n" << "Start packet capture...  [ TO STOP capture PRESS ANY KEY ]" << "\n\n";	
	
	pcap_loop(handle, 0, process_packet, (unsigned char*)file);   // начинаем захват пакетов

	pcap_close(handle);

	cout << "\n\nPacket capture completed!\n\n";

	SetConsoleMode(hInput, prevConsoleMode);                      // возврат прежних настроек консоли
	
	while (true) cin.get();
	
	return 0;
}