/*
 * INCLUDING THE PROPER LIBRARIES
 * DEPENDING ON OPERATING SYSTEM
 *
 * */

#if defined(unix) || defined(__unix__) || defined(__unix)
	#define PREDEF_PLATFORM_UNIX 1				// okay we are in a unix machine
	#include <sys/socket.h>					// including unix socket headers
	#include <netdb.h>					// needed for unix socket
	#include <netinet/in.h>					// for internet protocol family
	#include <unistd.h>					// needed for unix read/write
#elif defined(__WIN32)
	#define PREDEF_PLATFORM_MS 1				// now we are in a windows machine
	#include <winsock2.h>					// including ms socket headers
	#include <io.h>						// needed for ms read/write
	#pragma comment(lib, "ws2_32.lib")			// telling linker to link winsock library
#endif

#include <stdio.h>						// crossed platform headers
#include <string.h>						// string header, for strcpy
#include <stdlib.h>						// stardard lib, for exit()


// forward function declaration
void system_check();						// checking our operating system
void ms_init();							// initalizing microsoft systems
int try_listening();						// returns a file descriptor of socket upon success
void setting_opts(int fd);					// this will set all the options for the socket fd
void setting_serverInfo(struct sockaddr_in *server);		// this will do all the set up for socket server's network info
int recv_connection(int server_fd);				// returns a file descriptor of new client socket upon success
void ECHO(int file_descriptor);					// infinite loop echo serving client
char* vuln_func(char* recieved);				// BoF vulnerable function that uses strcpy from string.h
void closing_procedures(int server_fd, int clientComm_fd);	// closes all sockets


// main function
int main(int argc, char** argv)
{
	system_check();						// first we got to check which operating system we are in
								// the side effect of the systemcheck func is to print to stdo our info

	// initalizing variables
	int MAX_CONN = 1;					// max connection allowed for this tcp socket server
	int listen_fd, communicate_fd;				// file descriptors used for sockets
	struct sockaddr_in serv_addr;				// struct to store socket server address info

	#if PREDEF_PLATFORM_MS == 1				// if we are in a microsoft windows host system
		ms_init();
	#endif

	listen_fd = try_listening();				// returns a file descriptor upon successful listen from socket

	setting_opts(listen_fd);				// we will set options for this socket fd in this function

	setting_serverInfo((struct sockaddr_in*) &serv_addr);	// sets up the ip and port number to the declared struct serv_addr

	// binding using the bind method provided by socket.h: binding the socket returned file descriptor
	// with a struct pointer pointing to the address of server address struct declared earlier
	// we are binding struct pointer of sockaddr instead of sockaddr_in because bind and and accept only takes that struct
	// different struct sockaddr_in was used to configure it, because it has the more specific fields to set
	// and also need to feed the function the size of the server address struct
	bind(listen_fd, (struct sockaddr*) &serv_addr, sizeof(serv_addr));		//binding address to socket

	listen(listen_fd, MAX_CONN);							// after binding we listen for 5 connections

	printf("\n[!] We have sucessfully binded localhost IP, and listening on port 22000...\n");

	communicate_fd = recv_connection(listen_fd);		// returns a file descriptor of the new socket connection

	ECHO(communicate_fd);

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
#if PREDEF_PLATFORM_MS == 1
	WSADATA wsa;					// its address needed for initalizing windows socket api (WSA)

	memset((WSADATA*) &wsa, 0, sizeof(wsa));	// clearing memory for the winsock api obj
	if (WSAStartup(MAKEWORD(2,2), &wsa) != 0)					// initialzing wsa using wsastartup
	{
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
	int file_descriptor;
	file_descriptor = socket(AF_INET, SOCK_STREAM, 0);	// socket method from socket.h returns a file descriptor
								// takes params, af_inet = ip fam, sock_stream = tcp type socket
								// 0 for deafult protocol for the requets socket type
	if (file_descriptor == -1){
		printf("\n[!] We couldn't establish a socket descriptor for listening");
		printf("\n[!] Exiting...");
		exit(EXIT_FAILURE);
		return 1;
	}

	printf("\n[!] We have established a server socket\n");	// once the above function is successful, we have a server socket
	return file_descriptor;

}

void setting_opts(int fd)
{
	int yes = 1;										// yes for resuable address option

	

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void*) &yes, sizeof(int)) == -1){	// setting the socket options at socket level
												// not protocol lvl, with resuseable address
	
		printf("\n[!] We couldn't set the socket option for reusable address");		// with also the address of the interger 1
	       											// for yes, lets us re use addressees, 
												// and the size of that interger 
		printf("\n[!] Exiting...");
		exit(EXIT_FAILURE);
	}

	printf("\n[!] Success in setting the resuable address to true\n");
}


void setting_serverInfo(struct sockaddr_in* server)		//  the address of a sockaddr_in struct struct is passed in
{

	memset(server, 0, sizeof(*server));			// clearing memory for declared server addy info structure
								// takes in the address of declared struct, and the size to clear
								// it will place zero value bytes in the area pointed by the address
	server->sin_family = AF_INET;				// setting/populating up all the server address info
	server->sin_addr.s_addr = htons(INADDR_ANY);		// this script will allow any ip to connect
								// htons used to make sure right formatting before going into the struct
	server->sin_port = htons(22000);			// using port 22000, htons to ensure formatting
}								// notice the syntax using -> b/c 
								// that how we reference a pointer to structure's key properties

int recv_connection(int server_fd)
{
	int file_descriptor;
	// accept is a blocking call, blocking execution until a connection is made,
	// once made the accept method will return a new file descriptor for communication
	// takes in the socket file descriptor we are currently listening to,
	// a pointer to a socketaddr struct of the particular client socket, which is NULL for any,
	// third parameter NULL for size of struct

	#if PREDEF_PLATFORM_UNIX == 1
        	file_descriptor = accept(server_fd, (struct sockaddr*) NULL, NULL);
	#elif PREDEF_PLATFORM_MS == 1
        	file_descriptor = accept(server_fd, (struct sockaddr*) NULL, NULL);
	#endif

	if (file_descriptor == -1)
    	{
        printf("\n[!] Unable to establish connection with client, and get a communicate fd...\n");
        printf("\n[!] Shutting down..\n");
        exit(EXIT_FAILURE);
    	}

	printf("\n[!] We have found a connection, getting ready to EcHoOoo\n");
	return file_descriptor;

}


void ECHO(int file_descriptor)						// the main function serve to echo out to clients
{
	char *send_str;							// declaring the pointer to the string recieved from vulnFunc
	char recv_str[1024];						// variable declaration

	// infinite loop to echo serve clients
	while(1)

	{
		memset(recv_str, 0, sizeof(recv_str));			// clearing out echo_str that was declared earlier, notice passing in
        	send_str = (char*)calloc(101, sizeof(char));    	// calloc returns a pointer to the address of memory allocated and 
									// cleared for specified size, and type


		#if PREDEF_PLATFORM_UNIX == 1
	        	read(file_descriptor, recv_str, 1024);		// reading from a file descriptor, storing it in a string(char array)
		#elif PREDEF_PLATFORM_MS == 1
            		recv(file_descriptor, recv_str, 1024, 0);	// reading from a file descriptor, storing it in a string(char array),
									// using recv for ms apps, last param is for flag opt purposes,
                                                        		// we put 0, because  ms doc sucks
		#endif

		if (strlen(recv_str) == 0)				// to check if client terminates, the recived string,
									// or sent from client is emtpy,
		{							// because the client disconnects and sent a termination of program
			printf("\n[!] Client disconnected, getting ready to shut down...\n");
			break;						// and recieved string will eventually get a one that is no length string
		}							// while all other time its just waiting for client sender,
									// now breaking out loop

		printf("\n[!] Echoing back: %s\n", recv_str);		// printing info on our screen

		// this is where we have a BoF problem
		//send_str = vuln_func(recv_str);				// w/o limit test, memory buffer could over flow
		vuln_func(recv_str);					// grabbing the return value is a waste of time
									// and we wont be able to exploit the BoF prob in the vuln function

		// writing to the communicate file descriptor, writing it the send string
		// also inputting the size fo the send string's length plus 1, for the null terminator?

		#if PREDEF_PLATFORM_UNIX == 1
            		write(file_descriptor, recv_str, strlen(recv_str)+1);
        	#elif PREDEF_PLATFORM_MS == 1
            		send(file_descriptor, recv_str, strlen(recv_str)+1, 0);      	//using send for ms apps, and
											//the last params is for flag opt purposes,
											//we put 0, bc ms doc sucks
		#endif

	}

}


char* vuln_func( char* recieved)
{
	char* sending_str = (char*)calloc(100, sizeof(char));			// allocating space for the char array pointer 
    										// we will return to main function, 
										// this will work b/c calloc uses heap memory 
										// which will not die with function stack memory like send
	char send[100];								// initalizing the buffer for str copy
										// note it has to use stack memory to cause BoF
//	int i;									// declaring counter for loop
//
//	int* counter = (int*)calloc(1024, sizeof(int));				// intead of just int, we will use a counter inside an arr
										// which can be allocated in the heap, and wont affect the BoF
//										// exception, leaving it work behave the way its suppose to
//	counter[0] = 0;
	strcpy(send, recieved);
	
//	do
//	{
//		sending_str[counter[0]] = send[counter[0]];			// copying string value to the heap memory location at send_str
//		counter[0]++;							// incrementing the counter
//	}while(counter[0] < strlen(send));					// setting the condition 


	return sending_str;							// finally returning the heap allocated char arr/string
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
