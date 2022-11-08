#include "sniffer.h"
using namespace std;


int capture_packets = 0;                       // счётчик общего количества захваченных пакетов
int saved_packets = 0;                         // счётчик количества сохраненных в файл пакетов

vector<pcap_pkthdr> AllHeaders;                // для хранения pcap-заголовков захваченных пакетов
vector<vector<u_char>> AllPackets;             // для хранения содержимого захвачененых пакетов

int thread_flag = 0;                           // флаг состояния потока (1 - запущен, 0 - не запущен)
int close_flag = 0;                            // флаг состояния _kbhit (была остановка захвата или нет)

wstring enter_procname = L"NULL";              // для хранения введенного с консоли имени процесса
char num = '2';                                // для хранения введенного номера при диалоговом режиме
pcap_t* handle;                                // хэндл интерфейса для захвата
mutex m;                                       // мьютекс для синхронизации потоков
u_long ip_dev;                                 // для хранения IP-адреса выбранного интерфейса захвата


void threadFunction2()
{
	while (1)                                  // ожидаем остановку захвата пользователем
	{
		if (_kbhit())
		{
			pcap_breakloop(handle);            // прерываем захват новых пакетов
			close_flag = 1;		               // устанавливаем флаг завершения работы программы
			return;
		}
	}
}


void threadFunction(u_char* file, vector<pcap_pkthdr>& AllHeaders, vector<vector<u_char>>& AllPackets)
{	
	int dns_flag = 2;                // флаг-идентификатор dns-пакета 
	int t = 0;                       // счётчик DNS-пакетов
	int syn_flag = 0;                // счётчик TCPsyn-пакетов
	vector<int> dns_numbers;         // для хранения номеров DNS-пакетов
	vector<temp_buf> Temp(65535);    // для хранения содержимого DNS-пакетов
	
	for (int i = 0; ; i++)           // начинаем анализ каждого захваченного пакета
	{	
		while (i >= capture_packets)             
		{
			if (close_flag == 1)                  // если проанализированы все захваченные пакеты и был нажат <enter>,
			{                                     // то завершаем работу программы
				print_summary(capture_packets, saved_packets);   // печать итоговой информации после захвата
				return;                    
			}				                      // если проанализированы все пакеты, а новые ещё не были захвачены,
			else                                  // то приостанавливаем поток, чтобы не завершился цикл, т.е.
				this_thread::sleep_for(chrono::milliseconds(1)); // ждём нажатие <enter> либо поступление новых пакетов
		}
		
		m.lock();

		pcap_pkthdr AllHeaders_item = AllHeaders[i];       // сохраняем pcap-заголовок пакета
		vector<u_char> AllPackets_item = AllPackets[i];	   // сохраняем содержимое пакета

		m.unlock();

		// для хранения заголовков IP, TCP, UDP
		IPHeader* iph = NULL;  TCPHeader* tcph = NULL;  UDPHeader* udph = NULL;

		wstring process_name = L"Unknown process";             // для хранения имени процесса
		wstring dns_proc_name = L"Unknown process";            // для хранения имени процесса dns-пакета 

		iph = (IPHeader*)(&AllPackets_item[0] + 14);           // выделяем заголовок IP
		UINT ip_hlen = (UINT)((iph->ip_ver_hlen & 15) * 4);    // длина IP-заголовка
		
		if (iph->ip_protocol == IPPROTO_TCP)
		{
			tcph = (TCPHeader*)(&AllPackets_item[0] + 14 + ip_hlen);      // выделяем заголовок TCP
			process_name = GetTcpProcessName(iph, tcph, enter_procname);  // ищем связь пакета с процессом в ОС
		}
		else if (iph->ip_protocol == IPPROTO_UDP)
		{
			udph = (UDPHeader*)(&AllPackets_item[0] + 14 + ip_hlen);      // выделяем заголовок UDP
			process_name = GetUdpProcessName(iph, udph, enter_procname);  // ищем связь пакета с процессом в ОС
		}
		else
			continue;    // если это не пакет TCP или UDP, то переходим к анализу следующего пакета
		
		int is_dns = isDNS(tcph, udph);      // проверка, относится пакет к DNS (0,1) или нет (2)  

		if (is_dns != 2)                     
		{
			dns_numbers.push_back(i);        // запоминаем номер каждого DNS-пакета
			
			Temp[t].ipheader = *iph;		 // запоминаем его заголовок IP	

			if (udph != NULL)
				Temp[t].udpheader = *udph;   // запоминаем его заголовок UDP
			else if (tcph != NULL)
				Temp[t].tcpheader = *tcph;   // TCP неактуально для DNS, но на всякий случай пусть будет

			t++;			                 // итерация счётчика захваченных DNS-пакетов

			if (is_dns == 0)
				dns_flag = 0;                // DNS-запрос
			else
				dns_flag = 1;                // DNS-ответ
		}
		
		if (dns_flag == 1 && isTCPSyn(tcph))      // ищем первый пакет TCP-syn после DNS-ответа
		{
			string buf_ip;                   // буфер для хранения IP-адреса (для функции inet_ntop)			
			string temp;                     // хранит октет IP-адреса в виде строки
			vector<int> temp_ip(4, 0);       // хранит IP-адрес в виде четырёх чисел
			int j = 0;                       // переменная-счётчик для циклов

			// преобразуем IP-адрес в строку
			inet_ntop(AF_INET, &iph->ip_dst_addr, &buf_ip[0], 16);

			stringstream stream(buf_ip);
			while (getline(stream, temp, '.'))
			{
				temp_ip[j] = stoi(temp);     // перевод IP-адреса назначния в формат вектора из четырёх чисел
				j++;
			}

			for (int z = dns_numbers.size() - 1; z >= 0; z--)
			{
				// перевод содержимого DNS-пакета в формат кодов символов (int)

				vector<int> int_pack(AllPackets[dns_numbers[z]].size());  	

				for (j = 0; j < int_pack.size(); j++)
					int_pack[j] = AllPackets[dns_numbers[z]][j];

				// поиск IP адреса назначния TCP-syn пакета в DNS-пакете (так как после DNS-ответа
				// идёт пакет TCP c установкой соединения по одному из полученных адресов)

				auto it = search(int_pack.begin(), int_pack.end(), temp_ip.begin(), temp_ip.end());

				if (it != int_pack.end())          // если IP успешно найден, то захваченные DNS-пакеты связаны
				{                                  // с процессом этого TCP-пакета
					dns_proc_name = process_name;
					syn_flag = 5;
					break;
				}			
			}

			if (syn_flag != 5)  // предполагается, что IP из DNS-ответа является IP-адресом назначения ближайших   
				syn_flag++;     // 5-и TCPsyn-пакетов (если нет, то выведем потом dns-пакеты как unknown process)

			if (syn_flag >= 5)
			{
				if (enter_procname == L"NULL" || enter_procname == dns_proc_name)

					for (j = 0; j < dns_numbers.size(); j++)    // выводим сохраненные DNS-пакеты
					{
						saved_packets++;         // увеличиваем счетчик сохраненных пакетов

						if (num == '1')          // выводим пакет в консоль
							print_info(saved_packets, &Temp[j].ipheader, &Temp[j].tcpheader,
								&Temp[j].udpheader, dns_proc_name);

						wstring dns_proc_name1 = L"prc_name:" + dns_proc_name;  // сигнатура для диссектора Wireshark

						m.lock();

						// резервируем для вектора дополнительную память
						AllPackets[dns_numbers[j]].reserve(65535 + 1000);

						// вставляем в конец пакета имя процесса
						AllPackets[dns_numbers[j]].insert(AllPackets[dns_numbers[j]].begin()
							+ AllHeaders[dns_numbers[j]].caplen, dns_proc_name1.begin(), dns_proc_name1.end());

						// корректируем длину пакета в pcap-заголовке
						AllHeaders[dns_numbers[j]].caplen = AllHeaders[dns_numbers[j]].caplen + dns_proc_name1.size();
						AllHeaders[dns_numbers[j]].len = AllHeaders[dns_numbers[j]].caplen;

						// записываем пакет в файл
						pcap_dump(file, &AllHeaders[dns_numbers[j]], &AllPackets[dns_numbers[j]][0]);

						m.unlock();
					}

			    dns_numbers.clear();  // очищаем вектор с номерами DNS-пакетов
			    dns_flag = 2;         // устанавливаем флаг в начальное состояние
			    t = 0;                // обнуляем счетчик DNS-пакетов
				syn_flag = 0;         // обнуляем счетчик TCPsyn-пакетов
			}
		}
		else if (is_dns != 2) continue;  // если после DNS-ответа идут сразу другие DNS-пакеты, а не TCP-syn, то
		                                 // переходим к их анализу (сохранению) 


		// если пакет не DNS, то сразу выводим его, так как имя процесса для него определяется в этой же итерации

		if ((enter_procname == L"NULL" || enter_procname == process_name) && process_name != L"Reject")
		{
			saved_packets++;             

			if (num == '1')              
				print_info(saved_packets, iph, tcph, udph, process_name);

			process_name = L"prc_name:" + process_name;  // вcтавляем сигнатуру для диссектора Wireshark

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
		vector<u_char> temp_buf(Buffer, Buffer + header->caplen);  // преобразуем указатель захваченного пакета в вектор
		
		m.lock();

		AllPackets.push_back(temp_buf);                            // сохраняем каждый захваченный пакет
		AllHeaders.push_back(*header);                             // сохраняем каждый захваченный pcap-заголовок пакета  
		capture_packets++;		                                   // увеличиваем счётчик захваченных пакетов	

		m.unlock();

		if (thread_flag != 1)                                      // запускаем поток для анализа пакетов
		{                                                          
			thread_flag = 1;
			thread thr(threadFunction, file, ref(AllHeaders), ref(AllPackets));
			SetThreadPriority(thr.native_handle(), 2);             // повышаем приоритет потока
			thr.detach();                                          // поток работаем параллельно (пущен на "самотек")
		}
	}
}


int main(int argc, char *argv[])
{
	string errbuf;                       // буфер для хранения сообщения об ошибке
	vector<string> iface_name(100);      // буфер для хранения имён интерфейсов
	vector<u_long> iface_ip(100);        // буфер для хранения адресов интерфейсов 
	char count = '1';                    // количество доступных для захвата интерфейсов
	char iface_num = '1';                // номер выбранного интерфейса (1 - по умолчанию)	
	string wpcap_filter = "";            // буфер для хранения выражения winpcap фильтра
	int filter_flag = 0;                 // флаг (1 - в консоли есть аргумент для winpcap фильтра)
	bpf_program fp;                      // скомпилированный winpcap-фильтр


	if (argc > 1)                        // разбор аргументов командной строки
	{
		int arg_flag = 0;                // флаг (1 - аргумент, требующий ввода данных)
		
		for (int i = 0; i < argc; i++)
		{
			if (filter_flag == 1)        // cохраняем выражение фильтра после аргумента -f
			{
				wpcap_filter = wpcap_filter + string(argv[i]) + " ";
				continue;
			}
			
			if (string(argv[i]) == "--help" || string(argv[i]) == "-h")
			{
				print_help();            // вывод help
				exit(0);
			} else

			if (string(argv[i]) == "--list-interfaces" || string(argv[i]) == "-D")
			{
				print_ifaces(iface_name, iface_ip, argc, 1);   // вывод списка доступных для захвата интерфейсов
				exit(0);
			} else				

			if (string(argv[i]) == "-i" && i < argc - 1)       // считываем номер интерфейса для захвата
			{
				iface_num = argv[i+1][0];
				arg_flag = 1;
			} else	
			 
			if (string(argv[i]) == "-v")                       // режим работы с выводом пакетов в консоль
			{
				num = '1';
				arg_flag = 0;
			} else		

			if (string(argv[i]) == "-u" || string(argv[i]) == "--unknown") 
			{
				enter_procname = L"Unknown process";           // для захвата неопознанного по процессам трафика
				arg_flag = 0;
			} else				

			if ((string(argv[i]) == "-p" || string(argv[i]) == "--process-name") && i < argc - 1)
			{
				string temp(argv[i + 1]);                      // считываем имя процесса для фильтрации
				wstring temp1(temp.begin(), temp.end());
				enter_procname = temp1;
				arg_flag = 1;
			} else

			if ((string(argv[i]) == "-f" || string(argv[i]) == "--filter") && i < argc - 1)  // фильтры winpcap
			{
				filter_flag = 1;
				arg_flag = 1;
			} else

			if (argv[i][0] == '-' || (argv[i][0] != '-' && (arg_flag == 0 || arg_flag > 1) && i > 0))
				error_exit(10);                    
			else                                    // сообщение об ошибке, если введённый аргумент некорректен
				arg_flag = 2;
		}
	}


	// сохранение и/или вывод перечня IP-адресов в консоль (в диалоговом режиме)

	count = print_ifaces(iface_name, iface_ip, argc, 0);  


	// выполняется при запуске программы в диалоговом режиме (по щелчку на файл)
	
	if (argc <= 1)
	{
		cout << endl << "Please, enter the number of interface: ";

		// выбор интерфейса в консоли

		do
		{
			iface_num = _getche();
		} while (iface_num >= count || iface_num < '1');
	}


	// открываем хэндл для захвата пакетов с выбранного интерфейса

	handle = pcap_open_live(iface_name[iface_num - '0'].c_str(), 65535, 1, 1, &errbuf[0]);
	if (handle == NULL)
		error_exit(2);

	ip_dev = iface_ip[iface_num - '0'];             // сохранили IP-адрес выбранного интерфейса


	// выпонляется при запуске программы в диалоговом режиме (по щелчку на файл)
	
	if (argc <= 1)
	{
		cout << "\n\n\n\n" << "Use process filtering? (y/n): ";

		do
		{
			num = _getche();
		} while (num != 'y' && num != 'n');             // захват пакетов по определённому процессу (y) или нет (n)

		if (num == 'y')
		{
			cout << endl << endl << "Please, enter name of the process (for example, chrome.exe)";
			cout << endl << "or if you want to capture all non-process related traffic, type Unknown process: ";
			getline(wcin, enter_procname);		        // если (y), считываем с консоли имя процесса
		}                                               // оно должно быть точь-в-точь, как в выводе netstat
														// для захвата трафика, не связанного с процессами, необходимо
														// ввести строку Unknown process


		cout << "\n\n\n\n" << "Use winpcap-filters? (y/n): ";

		do
		{
			num = _getche();
		} while (num != 'y' && num != 'n');             // будет ввод выражения winpcap-фильтра (y) или нет (n)

		if (num == 'y')
		{
			cout << endl << endl << "Please, enter expression of winpcap captute filter (for example, port 80): ";			
			getline(cin, wpcap_filter);
			filter_flag = 1;
		}
	}


	if (filter_flag == 1)
	{
		if (pcap_compile(handle, &fp, wpcap_filter.c_str(), 0, ip_dev) == -1)  // компилируем winpcap-фильтр
			error_exit(8);

		if (pcap_setfilter(handle, &fp) == -1)                                 // устанавливаем winpcap-фильтр
			error_exit(9);
	}


	HANDLE hInput = GetStdHandle(STD_INPUT_HANDLE);    // отключаем режим быстрого редактирования в консоли
	DWORD prevConsoleMode;
	GetConsoleMode(hInput, &prevConsoleMode);
	SetConsoleMode(hInput, prevConsoleMode & ENABLE_EXTENDED_FLAGS);

	
	// выпонляется при запуске программы в диалоговом режиме (по щелчку на файл)
	
	if (argc <= 1)
	{
		cout << "\n\n\n\n" << "1. Short print in single-line format" << endl;
		cout << "2. Quiet mode. Only write to pcap file" << endl << endl;
		cout << "Please, select the mode: ";

		do                                          // выбор режима работы программы
		{
			num = _getche();
		} while (num != '1' && num != '2');
	}


	string filename;                                // для хранения имени pcap-файла
	SYSTEMTIME lt;                                  // для хранения временной отметки

	GetLocalTime(&lt);                              // получаем временную отметку для имени pcap-файла

	filename = to_string(lt.wYear) + "-" + to_string(lt.wMonth) + "-" + to_string(lt.wDay) + "-" +
		to_string(time(0)) + ".pcap";               // создали имя файла

	pcap_dumper_t* file = pcap_dump_open(handle, filename.c_str());     // создаем pcap-файл для записи пакетов
	if (file == NULL)
		error_exit(3);


	thread thr2(threadFunction2);       // запускаем поток, который отслеживает остановку захвата пользователем

	thr2.detach();                      // поток работает параллельно

	
	cout << "\n\n\n\n" << "Start packet capture...  [ TO STOP capture PRESS <ENTER> ]" << "\n\n";
	
	if (PCAP_ERROR == pcap_loop(handle, -1, process_packet, (unsigned char*)file))    // начинаем захват пакетов
		error_exit(7);


	if (capture_packets == 0)                               // выводим информацию, если не был захвачен ни один пакет
		print_summary(capture_packets, saved_packets);

	pcap_close(handle);                                     // закрываем хэндл

	SetConsoleMode(hInput, prevConsoleMode);                // возврат прежних настроек консоли	
	
	while (true) cin.get();
	
	return 0;
}