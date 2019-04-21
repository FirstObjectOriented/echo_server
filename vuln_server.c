/*
 * Simple TCP Echo Server
 * that contains the BoF vulnerable C function: 
 *  strcpy()
 *
 * */


 // loading OS dependencies
 // unix OSes
#if defined(unix) || defined(__unix__) || defined(__unix)
	#define PREDEF_PLATFORM_UNIX 1
	#include <sys/socket.h>
	#include <netdb.h>
	#include <netinet/in.h>
	#include <unistd.h>

// Microsoft Windows OSes
#elif defined(__WIN32)
	#define PREDEF_PLATFORM_MS 1
	#include <winsock2.h>
	#include <io.h>
	#pragma comment(lib, "ws2_32.lib")
#endif


// Croosed Platform headers
#include <stdio.h>
#include <string.h>
#include <stdlib.h>



// forward function declarations
void system_check();						           // checking for operating system
void ms_init();							          // initializes Microsoft systems
int try_listening();						         // returns a file descriptor of socket
void setting_opts(int fd);					        // set options for socket fd
void setting_serverInfo(struct sockaddr_in *server);			// set up for server's info
int recv_connection(int server_fd);				        // returns a file descriptor of new client connection upon success
void ECHO(int file_descriptor);					        // infinite loop echo serving client
void vuln_func( char* recieved);
void closing_procedures(int server_fd, int clientComm_fd);		// cleanup



// main function
int main(int argc, char** argv)
{

	// OS check
	system_check();


	// initializing variables
	int MAX_CONN = 1;
	int listen_fd, communicate_fd;
	struct sockaddr_in serv_addr;


	// Microsoft System initialization
	#if PREDEF_PLATFORM_MS == 1
		ms_init();
	#endif


	// create a socket for TCP port listening for connections
	// grab the socket file descriptor
	listen_fd = try_listening();


	// setting socket options
	setting_opts(listen_fd);


	// set up TCP server options
	setting_serverInfo((struct sockaddr_in*) &serv_addr);


	// bind server to socket
	bind(listen_fd, (struct sockaddr*) &serv_addr, sizeof(serv_addr));


    	// start TCP Socket server to listen for connections
	listen(listen_fd, MAX_CONN);


    	// output to user successful binding
	printf("\n[!] We have sucessfully binded localhost IP, and listening on port 22000...\n");



	// once connection is made (blocking call), grab new connection's file descriptor for communication purposes
	communicate_fd = recv_connection(listen_fd);



	// ECHO Service (contains vuln_func), echos back the same string sent from client
	ECHO(communicate_fd);


    	// clean up sockets
	closing_procedures(listen_fd, communicate_fd);	// closing up all sockets depending on host system


	return 0;


}



void system_check()
{

	// operating system platform check
	#if PREDEF_PLATFORM_UNIX == 1
		printf("\n[!] We are in an unix host\n");
	#elif PREDEF_PLATFORM_MS == 1
		printf("\n[!] We are in a ms host\n");
	#else
		printf("\n[!] Unable to identify the host machine");
		printf("[!] Exiting...\n");
		exit(EXIT_FAILURE);
	#endif
}



void ms_init()
{

// secondary check
#if PREDEF_PLATFORM_MS == 1

    	// declare and clear ms socket api object
	WSADATA wsa;
	memset((WSADATA*) &wsa, 0, sizeof(wsa));

	// initialize ms sockets
	if (WSAStartup(MAKEWORD(2,2), &wsa) != 0)
	{
		// ERRORS
		printf("\n[!] Error: %d\n", WSAGetLastError());
		printf("\n[!] Failed to initialize winsock api, shutting down...\n");
		exit(EXIT_FAILURE);			// exiting
	}else
	{
		printf("\n[!] Windows Socket API Initialized!\n");
	}
#endif
	
}



int try_listening()
{
    	// declare socket file descriptor to be returned
	int file_descriptor;
	file_descriptor = socket(AF_INET, SOCK_STREAM, 0);


	// ERRORS
	if (file_descriptor == -1)
	{
		printf("\n[!] We couldn't establish a socket descriptor for listening");
		printf("\n[!] Exiting...");
		exit(EXIT_FAILURE);
		return 1;
	}


	// Output and returns file descriptor
	printf("\n[!] We have established a tcp socket\n");
	return file_descriptor;

}

void setting_opts(int fd)
{
    	// tcp socket option
	int reuseable_address_yes = 1;


    	// set tcp socket option
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void*) &reuseable_address_yes, sizeof(int)) == -1)
	{
        	// ERRORS
		printf("\n[!] We couldn't set the socket option for reusable address");
		printf("\n[!] Exiting...");
		exit(EXIT_FAILURE);
	}
    	else
    	{
        	printf("\n[!] Success in setting the resuable address to true\n");
    	}
}



void setting_serverInfo(struct sockaddr_in* server)
{

    	// clear server struct from main, assume unworthy
	memset(server, 0, sizeof(*server));

	// setting/populating up the server IP family info
	server->sin_family = AF_INET;

	// allow any ip and specific port to connect & htons to ensure formatting
	server->sin_addr.s_addr = htons(INADDR_ANY);

	// using port 22000
	server->sin_port = htons(22000);
}

int recv_connection(int server_fd)
{
	int file_descriptor;

	// platform dependent accept
	// accept a connection from client, and grab its connection file descriptor to return
	#if PREDEF_PLATFORM_UNIX == 1
        	file_descriptor = accept(server_fd, (struct sockaddr*) NULL, NULL);
	#elif PREDEF_PLATFORM_MS == 1
        	file_descriptor = accept(server_fd, (struct sockaddr*) NULL, NULL);
	#endif


	if (file_descriptor == -1)
    {
        // ERRORS
        printf("\n[!] Unable to establish connection with client, and get a communicate fd...\n");
        printf("\n[!] Shutting down..\n");
        exit(EXIT_FAILURE);
    }
    else
    {
        printf("\n[!] We have found a connection, getting ready to EcHoOoo\n");
        return file_descriptor;
    }
}


void ECHO(int file_descriptor)
{

    // Initialize buffer needed for reading the communicating fd
	char recv_str[1024];


	// infinite loop to echo
	while(1)
	{
		// clearing out recv_str that could be used earlier
        	memset(recv_str, 0, sizeof(recv_str));


        	// platform dependent read/ receive
		#if PREDEF_PLATFORM_UNIX == 1
	        	read(file_descriptor, recv_str, 1024);
		#elif PREDEF_PLATFORM_MS == 1
                recv(file_descriptor, recv_str, 1024, 0);
		#endif


       		// LOOP END CONDITION, if client disconnects, and outputs 0 length strings
		if (strlen(recv_str) == 0)
		{
			printf("\n[!] Client disconnected, getting ready to shut down...\n");
			break;
		}



		// output to ensure we got a string from client
		printf("\n[!] Echoing back: %s\n", recv_str);


		// ** DANGEROUS FUNCTION ** this is where we have a BoF problem
       		vuln_func(recv_str);


		// platform dependent to send the received (same) string back to client
		#if PREDEF_PLATFORM_UNIX == 1
            		write(file_descriptor, recv_str, strlen(recv_str)+1);
        	#elif PREDEF_PLATFORM_MS == 1
            		send(file_descriptor, recv_str, strlen(recv_str)+1, 0);
		#endif
	}

}



void vuln_func( char* recieved)
{

    	// strcpy does NOT do boundary checks, therefore data from send can potentially leak through its memory in stack.
	char send[100];
	strcpy(send, recieved);


	return;
}

void closing_procedures(int server_fd, int clientComm_fd)
{

	#if PREDEF_PLATFORM_MS == 1
		printf("\n[!] Getting ready to shut down winsock api, and ms system\n");
		printf("\n[!] Closing socket, shutting off...\n");
		closesocket(clientComm_fd);
		closesocket(server_fd);
		WSACleanup();
	#elif PREDEF_PLATFORM_UNIX == 1
		printf("\n[!] Getting ready to shutdown unix system\n");
		printf("\n[!] Closing socket, shutting off...\n");
		close(clientComm_fd);
		close(server_fd);

	#endif
}
