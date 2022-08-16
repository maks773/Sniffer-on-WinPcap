#include "sniffer.h"
using namespace std;


int main(int argc, char *argv[])                  // основной код программы
{
	int err;                                      // хранит значение, возвращаемое функциями (код ошибки) 
	
	err = WSAStartup(MAKEWORD(2,2), &wsData);     // инициализация интерфейса сокетов с заданной версией
	if (err != 0) 
		error_exit(1);		

	s = socket(AF_INET, SOCK_RAW, 0);             // инициализация сокета
	if (s == INVALID_SOCKET) 
		error_exit(2);

	char host_buf[256];                           // для хранения имени хоста
	addrinfo hints = {}, *addrs, *addr;
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_RAW;
	hints.ai_protocol = IPPROTO_IP;

	err = gethostname(host_buf, sizeof(host_buf));    // получение имени хоста
	if (err == -1) 
		error_exit(3);

	err = getaddrinfo(host_buf, 0, &hints, &addrs);   // получение IP-адресов сетевых интерфейсов ОС
	if (err != 0)  		
	
	cout << "Select the interface to capture:" << endl << endl;
	
	char count = '1';                                 // вывод перечня IP-адресов в консоль 
	vector<sockaddr *> ip(100);	
	for (addr = addrs; addr != NULL; addr = addr->ai_next) {
		ip[count - '0'] = addr->ai_addr; char buf_ip[20];
		cout << count << ". " << inet_ntop(AF_INET, &((sockaddr_in*)ip[count - '0'])->sin_addr,
																						buf_ip, 16) << endl;
		count++;
	}
	
	char num;
    cout << endl << "Please, enter the number of interface: ";
	do                                               // выбор номера интерфейса
	{   
		num = _getche();
	}   while (num >= count || num < '1');

	err = bind(s, ip[num - '0'], sizeof(sockaddr));  // привязка сокета к выбранному интерфейсу
	if (err != 0)  
		error_exit(5);		
	
	freeaddrinfo(addrs);

	ULONG flag = RCVALL_ON; ULONG z = 0;             // переключаем сетевой интерфейс в неразборчивый режим
	err = WSAIoctl(s, SIO_RCVALL, &flag, sizeof(flag), NULL, 0, &z, NULL, NULL);
	if (err == SOCKET_ERROR) 
		error_exit(6);		

	wstring enter_procname = L"NULL";
	cout << "\n\n\n\n" << "Use process filtering? (y/n): ";
	do
	{
		num = _getche();
	} while (num != 'y' && num != 'n');             // захват пакетов по определённому процессу (y) или нет (n)

	if (num == 'y') {
		cout << endl << "Please, enter name of the process (for example, chrome.exe): ";
		getline(wcin, enter_procname);		        // если (y), считываем с консоли имя процесса
	}                                               // оно должно быть точь-в-точь, как в выводе netstat

	HANDLE hInput = GetStdHandle(STD_INPUT_HANDLE);    // отключаем режим быстрого редактирования в консоли
	DWORD prevConsoleMode;
	GetConsoleMode(hInput, &prevConsoleMode);
	SetConsoleMode(hInput, prevConsoleMode & ENABLE_EXTENDED_FLAGS);

	cout << "\n\n\n\n" << "1. Full print (IP, TCP/UDP headers + Packet Data)" << endl;
	cout << "2. Short print in single-line format" << endl;
	cout << "3. Quiet mode. Only write to pcap file" << endl << endl;
	cout << "Please, select the mode: ";
	do
	{
		num = _getche();
	} while (num != '1' && num != '2' && num != '3');   // выбор режима работы программы
	
	int p_count = 0;                                    // счётчик количества записанных пакетов
	HANDLE hFile = NULL;                                // хэндл для pcap-файла
	vector<temp_buf> Temp(65535);                       // для хранения пакетов между DNS-запросом и ответом
	vector<vector<BYTE>> Buf(65535);
	int t = 0;                                          // счётчик пакетов между DNS-запросом и ответом
	flag = 100;                                         // 100 - начальное состояние флага

	writehead_to_pcap(hFile);                           // запись глобального заголовка в pcap-файл

	cout << "\n\n" << "Start packet capture...  [ TO STOP capture PRESS ANY KEY ]" << "\n\n";	

	while( !_kbhit() ) // начинаем захват пакетов
	{
		vector<BYTE> Buffer(65535);                     // буфер для хранения захваченного пакета
		IPHeader* iph = NULL;  TCPHeader* tcph = NULL;  UDPHeader* udph = NULL;
		wstring process_name = L"Unknown process";      // для хранения имени процесса

 		int byte_rcv = recvfrom(s, (char*)&Buffer[0], (int)Buffer.size(), 0, NULL, 0); // получаем пакет из сети
		if (byte_rcv >= sizeof(IPHeader))
		{
			iph = (IPHeader *)&Buffer[0];                        // выделяем заголовок IP
			UINT ip_hlen = (UINT)((iph->ip_ver_hlen & 15)*4);    // длина IP-заголовка
			
			if (iph->ip_protocol == IPPROTO_TCP) {
				tcph = (TCPHeader*)(&Buffer[0] + ip_hlen);       // выделяем заголовок TCP
				process_name = GetTcpProcessName(iph, tcph, enter_procname); // ищем связь пакета с процессом в ОС
			}
			else if (iph->ip_protocol == IPPROTO_UDP) {
				udph = (UDPHeader*)(&Buffer[0] + ip_hlen);       // выделяем заголовок UDP
				process_name = GetUdpProcessName(iph, udph, enter_procname); // ищем связь пакета с процессом в ОС 
			}
			else
				continue;

			int is_dns = isDNS(tcph, udph);       // проверка, относится пакет к DNS (0,1) или нет (2)               
			
			if (is_dns == 2 && flag == 1) {       // обработка пакета после dns-ответа
				string buf_ip(16, '\0');  vector<int> temp_ip(4, 0);  int nn = 0;  string temp;
				inet_ntop(AF_INET, &iph->ip_dst_addr, (char*)buf_ip.c_str(), 16);				
				stringstream stream(buf_ip);

				while (getline(stream, temp, '.')) {
					temp_ip[nn] = stoi(temp);    // перевод IP-адреса назначния в формат массива из четырёх чисел
					nn++;
				}

				vector<int> int_pack(65535);	 // перевод пакета в формат кодов символов (int)		
				for (nn = 0; nn < 65535; nn++) int_pack[nn] = Buf[t - 1][nn];

				// поиск IP адреса назначния TCP пакета в DNS-ответе (так как после DNS-ответа
				// идёт пакет TCP c установкой соединения по одному из полученных адресов)
				auto it = search(int_pack.begin(), int_pack.end(), temp_ip.begin(), temp_ip.end());
				if (it != int_pack.end() && process_name != L"NULL") {
					for (int i = 0; i < t; i++) { // если адрес найден и TCP-пакет связан с процессом, то выводим
						p_count++;                // захваченные DNS-ответ, запрос и пакеты между ними,
						                          // так как DNS-пакеты тоже связаны с этим процессом
						if (num == '2')
							print_info(p_count, &Temp[i].ipheader, &Temp[i].tcpheader,
								&Temp[i].udpheader, process_name);
						else
							if (num == '1')
								print_packet(p_count, &Temp[i].ipheader,
									&Temp[i].tcpheader, &Temp[i].udpheader, process_name, Buf[i]);

						writepack_to_pcap(hFile, Buf[i], ntohs(Temp[i].ipheader.ip_length), process_name);						
					}
					t = 0; flag = 100;    // обнуляем счётчик и ставим флаг в начальое состояние
				}
				else {
					t = 0; flag = 100;
					continue;             // иначе переходим к захвату пакетов без вывода сохранённых
				}
			}
			
			if (is_dns != 2 || flag == 0) {	 // сохраняем пакеты между DNS-запросом и DNS-ответом			
				Temp[t].ipheader = *iph;
				if (udph != NULL)
					Temp[t].udpheader = *udph;
				else
					Temp[t].tcpheader = *tcph;
				Buf[t] = Buffer;  t++;
				if (is_dns == 0)             // DNS-запрос
					flag = 0;
				else if (is_dns == 1)        // DNS-ответ
						flag = 1;				
				continue;
			}


			if (process_name != L"NULL") {  // если захваченный пакет связан с процессом, выводим его
				p_count++;
				if (num == '2')
					print_info(p_count, iph, tcph, udph, process_name);
				else
					if (num == '1')
							print_packet(p_count, iph, tcph, udph, process_name, Buffer);

				writepack_to_pcap(hFile, Buffer, ntohs(iph->ip_length), process_name);
			}			
		}
	}

	cout << "\n\nPacket capture completed!\n\n";	
	SetConsoleMode(hInput, prevConsoleMode); // возврат прежних настроек консоли
	CloseHandle(hInput);
	CloseHandle(hFile);
	closesocket(s);
	WSACleanup();	
	system("pause");
	return 0;
}