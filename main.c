#ifdef __linux__
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#define OPEN_FLAGS		(O_RDONLY)
#define	closesocket		close

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#elif _WIN32
#define WIN32_LEAN_AND_MEAN
#include <w32api.h>
#define WINVER                  WindowsVista
#define _WIN32_WINDOWS          WindowsVista
#define _WIN32_WINNT            WindowsVista
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <io.h>
#include <stdio.h>
#define OPEN_FLAGS		(O_RDONLY|O_BINARY)
#pragma comment (lib, "Ws2_32.lib")
#include <fcntl.h>
#include <direct.h>
#else
#error "OS not supported"
#endif

#include <errno.h>
#include <limits.h>

#include "auth_login_token_t.h"


#define xstr(s) str(s)
#define str(s) #s

#define DEBUG_ENABLED 1
#if (DEBUG_ENABLED == 1)
#define PRINTF(...)  printf(__VA_ARGS__)
#define ERR_LOG(...) fprintf(stderr, __VA_ARGS__)
#else
#define PRINTF(...)
#define ERR_LOG(...)
#endif	/* DEBUG_ENABLED */


#define ALTOK_DELIVERY_PORTNUM  38972

static void handle_response(int sockfd)
{
    char recv_buf[128];
    int rc, i;
    int bytes_received;

    rc = recv(sockfd, recv_buf, sizeof(recv_buf), 0);
    if (rc == 0) {
	printf("Server-side disconnected.\n");
	return;
    }
    else if (rc < 0) {
	fprintf(stderr, "Error on recv(): %d (%s)\n", rc, strerror(errno));
	return;
    }
    bytes_received = rc;

    printf("Received from server:\n");
    for (i = 0; i < rc; i++) {
	if (recv_buf[i] & 0x80) {
	    // encountered a non-printable character
	    break;
	}
	printf("%c", recv_buf[i]);
    }
    printf("\n");
}

static void send_token(int sockfd, const unsigned char *tokendata, int token_length)
{
    int i, rc;
    int bytes_sent;
    unsigned int mac_addr[6];

    printf("Sending the token...\n");

    bytes_sent = 0;
    while (bytes_sent < token_length) {
	int count = send(sockfd, (const char*)(tokendata + bytes_sent), token_length - bytes_sent, 0);
	if (count < 0) {
	    fprintf(stderr, "Error on send()'ing the token: %d (%s)\n", count, strerror(errno));
	    return;
	}
	bytes_sent += count;
    }

    printf("Done.\n");
}

static int netlib_getsocket(const char *hostname, const char *portname,
			    int *psockfd, struct addrinfo **ppaddrinfo)
{
    int rc = 0;
    struct addrinfo hints;
    struct addrinfo *addr_info;
    int portnum;
    int sockfd;

    *ppaddrinfo = NULL;
    memset(&hints, 0, sizeof hints); // make sure the struct is empty
    hints.ai_family   = AF_UNSPEC;   // don't care IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM; // TCP stream sockets
    hints.ai_flags    = AI_PASSIVE;  // fill in my IP for me
    
    if ((rc = getaddrinfo(hostname, portname, &hints, &addr_info)) != 0) {
	ERR_LOG("getaddrinfo error: %s\n", gai_strerror(rc));
	return -1;
    }

    // addr_info now points to a linked list of 1 or more struct addrinfos
    PRINTF("Hostname IP addresses are:\n");
    {
	bool valid_addr_info_found = false;
	struct addrinfo *pinfo;
	for (pinfo = addr_info; pinfo != NULL; pinfo = pinfo->ai_next) {
	    void *addr;
	    char ipver[16];
	    char ipstr[INET6_ADDRSTRLEN];

	    // get the pointer to the address itself,
	    // different fields in IPv4 and IPv6:
	    if (pinfo->ai_family == AF_INET) { // IPv4
		struct sockaddr_in *ipv4 = (struct sockaddr_in *)pinfo->ai_addr;
		addr = &(ipv4->sin_addr);
		portnum = ipv4->sin_port;
		strcpy(ipver, "IPv4");
	    } else { // IPv6
		struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)pinfo->ai_addr;
		addr = &(ipv6->sin6_addr);
		portnum = ipv6->sin6_port;
		strcpy(ipver, "IPv6");
	    }

	    // convert the IP to a string and print it:
	    inet_ntop(pinfo->ai_family, addr, ipstr, sizeof(ipstr));
	    PRINTF("  %s: %s:%d\n", ipver, ipstr, ntohs(portnum));
	    valid_addr_info_found = true;
	}

	if (!valid_addr_info_found) {
	    ERR_LOG("Could not find valid info for this hostname.\n");
	    return -1;
	}
    }

    rc = socket(addr_info->ai_family, addr_info->ai_socktype, addr_info->ai_protocol);
    if (rc < 0) {
	ERR_LOG("Error on socket() call: %d (%s)\n", sockfd, strerror(errno));
	return -1;
    }
    sockfd = rc;

    *ppaddrinfo = addr_info;
    *psockfd = sockfd;

    return 0;
}


int main(int argc, char *argv[])
{
    int rc = 0;
    struct addrinfo *srvr_info = NULL;
    int sockfd;
    int tokenfd;
    unsigned char tokendata[sizeof(auth_login_token_t)];
#ifdef _WIN32
    int iResult;
    WSADATA wsaData;
#endif
    
    printf("auth_login_token_delivery running...\n");

    if (argc < 3) {
	fprintf(stderr, "Usage: %s <target-box-IP-address> <ALTok>\n"
		"        E.g.: ./auth_login_token_delivery 10.15.10.195 fpt-1554340960.00000001-MAC_001122ddeeff.alt\n",
		argv[0]);
	return -1;
    }

#ifdef _WIN32
    // Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
    if (iResult != 0) {
        printf("WSAStartup failed with error: %d\n", iResult);
        return 1;
    }
#endif

    tokenfd = open(argv[2], OPEN_FLAGS);
    if (tokenfd < 0) {
	ERR_LOG("Error: unable to open Token file: [%s]\n", argv[2]);
	return -2;
    }
    rc = read(tokenfd, tokendata, sizeof(tokendata));
    close(tokenfd);
    if (rc != sizeof(tokendata)) {
	ERR_LOG("Unable to read the token file [%s] : rc=%d\n", argv[2], rc);
	return -3;
    }

    rc = netlib_getsocket(argv[1], xstr(ALTOK_DELIVERY_PORTNUM), &sockfd, &srvr_info);
    if (rc < 0) {
	ERR_LOG("Error from netlib_getsocket(): %d\n", rc);
	goto clean_exit;
    }

    rc = connect(sockfd, srvr_info->ai_addr, srvr_info->ai_addrlen);
    if (rc < 0) {
	ERR_LOG("Error on connect() call: %d (%s)\n", rc, strerror(errno));
	goto clean_exit;
    }

    send_token(sockfd, tokendata, sizeof(tokendata));
    handle_response(sockfd);

    /* For portability with Windows, which has close() for files 
     * and closesocket() for sockets.
     */ 
    closesocket(sockfd); // macro'd close() for linux 
    
clean_exit:
    if (srvr_info != NULL)
	freeaddrinfo(srvr_info); // free the linked-list

#ifdef _WIN32
    WSACleanup();
#endif

    return rc;
}
