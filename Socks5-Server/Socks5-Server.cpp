#include<iostream>
#include<thread>
#include<vector>

#include<Ws2tcpip.h>
#include<winsock2.h>
#include<Windows.h>

#pragma comment(lib, "Ws2_32.lib")
using namespace std;

#define METHOD_NUMBER 2
const char method_numbers[METHOD_NUMBER] =
{
	0,
	2
};

void sendReply(SOCKET c, char replyField, char addressType, char* addr, char* port)
{
	char answer[300];
	char null[20];
	int ret;

	memset(answer, 0, 300);
	memset(null, 0, 20);

	// if addr or port set to NULL, we will send nulls instead of the address
	// it isn't RFC compliant but I do not support info leak either.
	if (addr == NULL) addr = null;
	if (port == NULL) port = null;

	answer[0] = 5;

	answer[1] = replyField;
	answer[3] = addressType;

	switch (addressType)
	{
	case 3:
		memcpy_s(answer + 4, 296, (void*)(addr + 1), (unsigned char)(addr[0]));
		memcpy_s(answer + 4 + (unsigned char)(addr[0]), 396 - (unsigned char)(addr[0]), port, 2);
		break;
	case 4:
		memcpy_s(answer + 4, 296, addr, 16);
		memcpy_s(answer + 20, 280, port, 2);
		ret = 22;
		break;
	default:
		memcpy_s(answer + 4, 296, addr, 4);
		memcpy_s(answer + 8, 292, port, 2);
		ret = 10;
		break;
	}
	if ((ret = send(c, answer, ret, 0)) == SOCKET_ERROR)
	{
		printf("[-] SOCKS thread(%d) sendReply send error: %ld %ld\n", GetCurrentThreadId(), ret, WSAGetLastError());
	}
}

int getAddressInfo(sockaddr_in* sockaddrin, sockaddr_in6* sockaddrin6, char* buf, int ret)
{
	ADDRINFOA hints;
	ADDRINFOA* result = NULL;

	char domain[256];

	//IPv4
	if (buf[3] == 1)
	{
		if (ret != 10)
		{
			printf("[-] SOCKS thread(%d) getAddressInfo IPv4 selected, length mismatch: %ld\n", GetCurrentThreadId(), ret);
			return -1;
		}
		sockaddrin->sin_family = AF_INET;
		memcpy_s(&(sockaddrin->sin_port), 2, buf + 8, 2);
		memcpy_s(&(sockaddrin->sin_addr), 4, buf + 4, 4);

		char* s = (char*)malloc(INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &(sockaddrin->sin_addr), s, INET_ADDRSTRLEN);
		printf("[+] SOCKS thread(%d) getAddressInfo CONNECT IPv4: %s:%hd\n", GetCurrentThreadId(), s, htons(sockaddrin->sin_port));
		free(s);
	}
	//DNS
	if (buf[3] == 3)
	{
		if ((7 + (unsigned char)buf[4]) != ret)
		{
			printf("[-] SOCKS thread(%d) getAddressInfo DNS selected, length mismatch: %ld\n", GetCurrentThreadId(), ret);
			return -1;
		}
		ZeroMemory(&hints, sizeof(hints));
		ZeroMemory(domain, 256);

		// change for IPv6?
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;
		hints.ai_flags = AI_PASSIVE;

		memcpy_s(domain, 256, (void*)(buf + 5), (unsigned char)(buf[4]));

		if ((ret = GetAddrInfoA(domain, "1", &hints, &result)) != 0) {
			printf("[-] SOCKS thread(%d) getAddressInfo GetAddrInfoA failed with error: %ld %ld\n", GetCurrentThreadId(), ret, WSAGetLastError());
			return -1;
		}
		memcpy_s(sockaddrin, sizeof(sockaddr_in), result->ai_addr, sizeof(sockaddr_in));
		memcpy_s(&(sockaddrin->sin_port), 2, buf + ((unsigned char)buf[4]) + 5, 2);

		char* s = (char*)malloc(INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &(sockaddrin->sin_addr), s, INET_ADDRSTRLEN);
		printf("[+] SOCKS thread(%d) getAddressInfo CONNECT DNS: %s(%s):%hd\n", GetCurrentThreadId(), domain, s, htons(sockaddrin->sin_port));
		free(s);
	}
	//IPv6
	if (buf[3] == 4)
	{
		if (ret != 22)
		{
			printf("[-] SOCKS thread(%d) getAddressInfo IPv6 selected, length mismatch: %ld\n", GetCurrentThreadId(), ret);
			return -1;
		}
		sockaddrin6->sin6_family = AF_INET6;
		memcpy_s(&(sockaddrin6->sin6_port), 2, buf + 20, 2);
		memcpy_s(&(sockaddrin6->sin6_addr), 30, buf + 4, 16);

		char* s = (char*)malloc(INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, &(sockaddrin6->sin6_addr), s, INET6_ADDRSTRLEN);
		printf("[+] SOCKS thread(%d) getAddressInfo CONNECT IPv6: %s:%hd\n", GetCurrentThreadId(), s, htons(sockaddrin6->sin6_port));
		free(s);
	}

	return 0;
}

SOCKET DoConnection(SOCKET c, char* buf, int ret)
{
	SOCKET sock;
	sockaddr_in sockaddrin;
	sockaddr_in6 sockaddrin6;

	if (buf[0] == 5)
	{
		if (getAddressInfo(&sockaddrin, &sockaddrin6, buf, ret) < 0) {
			printf("[-] SOCKS thread(%d) DoConnection could not create socket structs\n", GetCurrentThreadId());
			// this isnt "general SOCKS server failure", but there no better error code
			sendReply(c, 0x01, 0x01, NULL, NULL);
			return NULL;
		}

		// CONNECT
		if (buf[1] == 1)
		{
			if (buf[3] == 4)
			{
				if ((sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET) {
					printf("[-] SOCKS thread(%d) DoConnection socket6() failed with: %ld\n", GetCurrentThreadId(), WSAGetLastError());
					sendReply(c, 0x01, 0x04, NULL, NULL);
					return NULL;
				}

				if ((ret = connect(sock, (SOCKADDR*)&sockaddrin6, sizeof(sockaddrin6))) == SOCKET_ERROR) {
					printf("[-] SOCKS thread(%d) DoConnection connect6() failed with: %ld\n", GetCurrentThreadId(), WSAGetLastError());
					sendReply(c, 0x05, 0x04, NULL, NULL);
					return NULL;
				}
			}
			else
			{
				if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET) {
					printf("[-] SOCKS thread(%d) DoConnection socket() failed with: %ld\n", GetCurrentThreadId(), WSAGetLastError());
					sendReply(c, 0x01, 0x01, NULL, NULL);
					return NULL;
				}

				if ((ret = connect(sock, (SOCKADDR*)&sockaddrin, sizeof(sockaddrin))) == SOCKET_ERROR) {
					printf("[-] SOCKS thread(%d) DoConnection connect() failed with: %ld\n", GetCurrentThreadId(), WSAGetLastError());
					sendReply(c, 0x05, 0x01, NULL, NULL);
					return NULL;
				}
			}

			sendReply(c, 0x00, 0x01, NULL, NULL);

			return sock;
		}
		// BIND
		if (buf[1] == 2)
		{
			wprintf(L"[+] SOCKS DoConnection BIND\n");
		}
		// UDP ASSOCIATE
		if (buf[1] == 3)
		{
			//SOCK_DGRAM
			wprintf(L"[+] SOCKS DoConnection UDP ASSOCIATE\n");
		}
	}
	else
	{
		printf("[-] SOCKS thread(%d) DoConnection unknown SOCKS version\n", GetCurrentThreadId());
		return NULL;
	}

	return NULL;
}

int CheckAuthentication(SOCKET client, char* buffer, int ret)
{
	int i, j;
	char answer[2];

	answer[0] = 5;

	for (i = 0; i < METHOD_NUMBER; i++)
		for (j = 0; j < buffer[1]; j++)
			if (buffer[j + 2] == method_numbers[i])
			{
				answer[1] = method_numbers[i];
				if ((ret = send(client, answer, 2, 0)) == SOCKET_ERROR)
				{
					printf("[-] SOCKS thread(%d) CheckAuthentication: %ld\n", GetCurrentThreadId(), ret);
				}
				return method_numbers[i];
			}

	answer[1] = (unsigned)0xFF;

	if ((ret = send(client, answer, 2, 0)) == SOCKET_ERROR)
	{
		printf("[-] SOCKS thread(%d) CheckAuthentication NO ACCEPTABLE METHODS %ld\n", GetCurrentThreadId(), ret);
		return i;
	}

	return -1;
}

void HandleAccept(SOCKET client)
{
	SOCKET relay = 0;
	const int buffsize = 1024;
	char buffer[buffsize];
	int ret;
	int authnum = -1;

	fd_set readfds;

	ret = recv(client, buffer, sizeof(buffer), 0);
	if (ret == SOCKET_ERROR)
	{
		printf("[-] SOCKS thread(%d) HandleClient recv error: %ld %ld\n", GetCurrentThreadId(), ret, WSAGetLastError());
		goto ExitThread;
	}

	if (buffer[0] == 4)
	{
		printf("[-] SOCKS thread(%d) HandleClient Socks4 request\n", GetCurrentThreadId());
		goto ExitThread;
	}

	if (buffer[0] != 5)
	{
		printf("[-] SOCKS thread(%d) HandleClient unknown Socks version number\n", GetCurrentThreadId());
		goto ExitThread;
	}

	if (ret - 2 != buffer[1])
	{
		printf("[-] SOCKS thread(%d) HandleClient wrong list length: %ld\n", GetCurrentThreadId(), ret);
	}

	authnum = CheckAuthentication(client, buffer, ret);
	if (authnum < 0)
	{
		printf("[-] SOCKS thread(%d) HandleClient auth failed: %ld\n", GetCurrentThreadId(), authnum);
		goto ExitThread;
	}

	ret = recv(client, buffer, sizeof(buffer), 0);
	if (ret > 6)
	{
		relay = DoConnection(client, buffer, ret);
		//relay = DoConnection(relay, buffer, ret);
		if (relay == NULL)
		{
			printf("[-] SOCKS thread(%d) HandleClient no socket created\n", GetCurrentThreadId());
			goto ExitThread;
		}
	}
	else
	{
		printf("[-] SOCKS thread(%d) HandleClient connection request recv error: %ld %ld\n", GetCurrentThreadId(), ret, WSAGetLastError());
		goto ExitThread;
	}

	while (1)
	{
		FD_ZERO(&readfds);
		FD_SET(client, &readfds);
		FD_SET(relay, &readfds);
		if (select(NULL, &readfds, NULL, NULL, NULL) > 0)
		{
			if (FD_ISSET(client, &readfds))
			{
				int recvSize = recv(client, buffer, buffsize, 0);
				if (recvSize <= 0)
				{
					printf("[-] SOCKS thread(%d) recv error: %ld %ld\n", GetCurrentThreadId(), ret, WSAGetLastError());
					goto ExitThread;
				}
				int sendSize = send(relay, buffer, recvSize, NULL);
				printf("[+] client->relay sendSize: %d\n", sendSize);
			}
			if (FD_ISSET(relay, &readfds))
			{
				int recvSize = recv(relay, buffer, buffsize, 0);
				if (recvSize <= 0)
				{
					printf("[-] SOCKS thread(%d) recv error: %ld %ld\n", GetCurrentThreadId(), ret, WSAGetLastError());
					goto ExitThread;
				}
				int sendSize = send(client, buffer, recvSize, NULL);
				printf("[+] relay->client sendSize: %d\n", sendSize);
			}
		}
		else
		{
			printf("[-] SOCKS thread(%d) select time out\n", GetCurrentThreadId());
			goto ExitThread;
		}
	}

ExitThread:
	printf("[+] Exiting Thread \n");
	closesocket(client);
	closesocket(relay);
}

int main()
{
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
	{
		printf("[-] SOCKS WSAStartup() failed with error: %ld\n", WSAGetLastError());
		return -1;
	}

	SOCKET server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (server == INVALID_SOCKET)
	{
		printf("[-] SOCKS socket() failed with error: %ld\n", WSAGetLastError());
		WSACleanup();
		return -1;
	}

	struct sockaddr_in serverAddr;
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(2805);
	serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);

	if (bind(server, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)
	{
		printf("[-] SOCKS bind() failed with error: %ld\n", WSAGetLastError());
		return -1;
	}

	if (listen(server, SOMAXCONN) == SOCKET_ERROR)
	{
		printf("[-] SOCKS listen() failed with error: %ld\n", WSAGetLastError());
		return -1;
	}

	SOCKET client;
	while (1)
	{
		client = accept(server, NULL, NULL);
		if (client == INVALID_SOCKET)
		{
			printf("[-] SOCKS accept() failed with error: %ld\n", WSAGetLastError());
			break;
		}
		printf("[+] SOCKS Client connected, starting thread\n");
		std::thread t(HandleAccept, client);
		t.detach();
	}

	printf("[*] Closing down SOCKS Server\n");
	WSACleanup();
	closesocket(server);
	return 0;
}