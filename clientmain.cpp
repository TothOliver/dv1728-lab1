#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* You will to add includes here */
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <protocol.h>

// Enable if you want debugging to be printed, see examble below.
// Alternative, pass CFLAGS=-DDEBUG to make, make CFLAGS=-DDEBUG
#define DEBUG


// Included to get the support library
#include <calcLib.h>

int udp_client(const char *host, const char *port, const char *path);
int tcp_client(const char *host, const char *port, const char *path);

int calc(const char arith[], int v1, int v2);

int main(int argc, char *argv[]){
  
  
  
  if (argc < 2) {
    fprintf(stderr, "Usage: %s protocol://server:port/path.\n", argv[0]);
    exit(EXIT_FAILURE);
  }
  
  /*
    Read first input, assumes <ip>:<port> syntax, convert into one string (Desthost) and one integer (port). 
     Atm, works only on dotted notation, i.e. IPv4 and DNS. IPv6 does not work if its using ':'. 
  */
    char protocolstring[6], hoststring[2000],portstring[6], pathstring[7];

    char *input = argv[1];
    
    /* Some error checks on string before processing */
    // Check for more than two consequtive slashes '///'.

    if (strstr(input, "///") != NULL ){
      printf("Invalid format: %s.\n", input);
      return 1;
    }
    

    // Find the position of "://"
    char *proto_end = strstr(input, "://");
    if (!proto_end) {
        printf("Invalid format: missing '://'\n");
        return 1;
    }

     // Extract protocol
    size_t proto_len = proto_end - input;
    if (proto_len >= sizeof(protocolstring)) {
        fprintf(stderr, "Error: Protocol string too long\n");
        return 1;
    }
    
    // Copy protocol
    strncpy(protocolstring, input, proto_end - input);
    protocolstring[proto_end - input] = '\0';

    // Move past "://"
    char *host_start = proto_end + 3;

    // Find the position of ":"
    char *port_start = strchr(host_start, ':');
    if (!port_start || port_start == host_start) {
	printf("Error: Port is missing or ':' is misplaced\n");
        return 1;
    }

    // Extract host
    size_t host_len = port_start - host_start;
    if (host_len >= sizeof(hoststring)) {
        printf("Error: Host string too long\n");
        return 1;
    }
    
    // Copy host
    strncpy(hoststring, host_start, port_start - host_start);
    hoststring[port_start - host_start] = '\0';

        // Find '/' which starts the path
    char *path_start = strchr(host_start, '/');
    if (!path_start || *(path_start + 1) == '\0') {
        fprintf(stderr, "Error: Path is missing or invalid\n");
        return 1;
    }

    // Extract path
    if (strlen(path_start + 1) >= sizeof(pathstring)) {
        fprintf(stderr, "Error: Path string too long\n");
        return 1;
    }
    strcpy(pathstring, path_start + 1);

    // Extract port


    size_t port_len = path_start - port_start - 1;
    if (port_len >= sizeof(portstring)) {
        fprintf(stderr, "Error: Port string too long\n");
        return 1;
    }
    strncpy(portstring, port_start + 1, port_len);
    portstring[port_len] = '\0';

    // Validate port is numeric
    for (size_t i = 0; i < strlen(portstring); ++i) {
        if (portstring[i] < '0' || portstring[i] > '9') {
            fprintf(stderr, "Error: Port must be numeric\n");
            return 1;
        }
    }


    
    char *protocol, *Desthost, *Destport, *Destpath;
    protocol=protocolstring;
    Desthost=hoststring;
    Destport=portstring;
    Destpath=pathstring;
      
  // *Desthost now points to a sting holding whatever came before the delimiter, ':'.
  // *Dstport points to whatever string came after the delimiter. 


    
  /* Do magic */
  int port=atoi(Destport);
  if (port < 1 or port >65535) {
    printf("Error: Port is out of server scope.\n");
    if ( port > 65535 ) {
      printf("Error: Port is not a valid UDP or TCP port.\n");
    }
    return 1;
  }
#ifdef DEBUG 
  printf("Host %s and port %s.\n",Desthost, Destport);
#endif
  
  if((strcmp(protocol, "UDP") == 0 || strcmp(protocol, "udp") == 0) && ((strcmp(Destpath, "binary") == 0) || (strcmp(Destpath, "text") == 0))){
    return udp_client(Desthost, Destport, Destpath);
  }
  else if((strcmp(protocol, "TCP") == 0 || strcmp(protocol, "tcp") == 0) && ((strcmp(Destpath, "binary") == 0) || (strcmp(Destpath, "text") == 0))){
    return tcp_client(Desthost, Destport, Destpath);
  }
  else if ((strcmp(protocol, "ANY") == 0 || strcmp(protocol, "any") == 0) && strcmp(Destpath, "text") == 0){
    int any = tcp_client(Desthost, Destport, Destpath);
    if(any == EXIT_FAILURE){
      udp_client(Desthost, Destport, Destpath);
    }
  }
  else{
    fprintf(stderr, "Error: Protocol or path not supported\n");
    return EXIT_FAILURE;
  }
  

}

int udp_client(const char *host, const char *port, const char *path){
  struct addrinfo hints, *results;
  int sockfd;

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;

  int status = getaddrinfo(host, port, &hints, &results);
  if(status != 0 || results == NULL)
  {
    fprintf(stderr, "ERROR: RESOLVE ISSUE");
    return EXIT_FAILURE;
  }

  char ipstr[INET6_ADDRSTRLEN]; 
  for(struct addrinfo *p = results; p != NULL; p = p->ai_next) {
    void *addr;

    if(p->ai_family == AF_INET){
      struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
      addr = &(ipv4->sin_addr);
    }
    else if(p->ai_family == AF_INET6){
      struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
      addr = &(ipv6->sin6_addr);
    }
    else {
      fprintf(stderr, "Error: Not a valid IP-version\n");
      return EXIT_FAILURE;
    }

    inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);

    sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if(sockfd == -1) {
      fprintf(stderr, "ERROR: socket failed\n");
      return EXIT_FAILURE;
    }
  }

  if(strcmp(path, "binary") == 0){
    calcMessage cmsg = {0};
    cmsg.type = htons(22);
    cmsg.message = htons(0);
    cmsg.protocol = htons(17);
    cmsg.major_version = htons(1);
    cmsg.minor_version = htons(1);

    ssize_t sent = sendto(sockfd, &cmsg, sizeof(cmsg), 0, results->ai_addr, results->ai_addrlen);
    if(sent != sizeof(cmsg)){
      freeaddrinfo(results);
      close(sockfd);
      fprintf(stderr, "ERROR: sendto failed\n");
      return EXIT_FAILURE;
    }
  
    fd_set reading;
    struct timeval timeout;
    int rc;

    while(true){
        char buf[1500];
        struct sockaddr_storage addr;
        socklen_t addr_len = sizeof(addr);
        ssize_t byte_size;

        FD_ZERO(&reading);
        FD_SET(sockfd, &reading);
        memset(&timeout, 0, sizeof(timeout));

        timeout.tv_sec = 2;
        rc = select(sockfd+1, &reading, NULL, NULL, &timeout);

        if(rc > 0){
          byte_size = recvfrom(sockfd, buf, sizeof(buf), 0, (struct sockaddr*)&addr, &addr_len);
        }else if(rc == 0){
            freeaddrinfo(results);
            close(sockfd);
            fprintf(stderr, "ERROR: TIMEOUT\n");
            return EXIT_FAILURE;
        }else{
          perror("select");
        }
        
        if(byte_size <= 0)
        {
          freeaddrinfo(results);
          close(sockfd);
          break;
        }
        else if(byte_size == sizeof(calcMessage)){ //12 bytes
          calcMessage respons;            
          memcpy(&respons, buf, sizeof(respons));
          uint16_t type = ntohs(respons.type);
          uint32_t message = ntohl(respons.message);
          uint16_t protocol = ntohs(respons.protocol);
          uint16_t majorv= ntohs(respons.major_version);
          uint16_t minorv = ntohs(respons.minor_version);

          printf("Got calcMessage: type=%u, message=%u, proto=%u, major=%u, minor=%u\n",
                type, message, protocol, majorv, minorv);

          if(message == 1){
            printf("Server reply: OK\n");
            return EXIT_SUCCESS;
          }       
          if(message == 2){
            printf("Server reply: NOT OK\n");
            return EXIT_FAILURE;
          }       
        }
        else if(byte_size == sizeof(calcProtocol)){ //26 bytes
          calcProtocol respons;
          memcpy(&respons, buf, sizeof(respons));

          uint32_t arith = ntohl(respons.arith);
          int32_t inValue1 = ntohl(respons.inValue1);
          int32_t inValue2 = ntohl(respons.inValue2);
          int32_t inResult = 0;
            
          if(arith == 1)
            inResult = inValue1 + inValue2;
          else if(arith == 2)
            inResult = inValue1 - inValue2;
          else if(arith == 3)
            inResult= inValue1 * inValue2;
          else if(arith == 4)
            inResult= inValue1 / inValue2;

          respons.type = htons(2);
          respons.inResult = htonl(inResult);

          ssize_t sent = sendto(sockfd, &respons, sizeof(respons), 0, results->ai_addr, results->ai_addrlen);
          if(sent != sizeof(respons)){
            freeaddrinfo(results);
            close(sockfd);
            fprintf(stderr, "ERROR: sendto failed\n");
            return EXIT_FAILURE;
          }
            printf("Respons Size:%lu\n", sizeof(respons));
          }
          else{
            printf("Byte_size:%lu\n", byte_size);
            fprintf(stderr, "ERROR: wrong size or incorrect protocol\n");
            return EXIT_FAILURE;
          }
        }
  }

  else if(strcmp(path, "text") == 0){
    char tmsg[] = "TEXT UDP 1.1\n";

    ssize_t sent = sendto(sockfd, tmsg, strlen(tmsg), 0, results->ai_addr, results->ai_addrlen);
    if(sent == -1){
      freeaddrinfo(results);
      close(sockfd);
      fprintf(stderr, "ERROR: sendto failed\n");
      return EXIT_FAILURE;
    }

    fd_set reading;
    struct timeval timeout;
    int rc;

    while(true){
        char buf[1500];
        memset(&buf, 0, sizeof(buf));
        struct sockaddr_storage addr;
        socklen_t addr_len = sizeof(addr);
        ssize_t byte_size;

        FD_ZERO(&reading);
        FD_SET(sockfd, &reading);
        memset(&timeout, 0, sizeof(timeout));
        timeout.tv_sec = 2;
        rc = select(sockfd+1, &reading, NULL, NULL, &timeout);

        if(rc > 0){
          byte_size = recvfrom(sockfd, buf, sizeof(buf), 0, (struct sockaddr*)&addr, &addr_len);
        }else if(rc == 0){
            freeaddrinfo(results);
            close(sockfd);
            fprintf(stderr, "ERROR: TIMEOUT\n");
            return EXIT_FAILURE;
        }else{
          perror("select");
        }
        
        if(byte_size <= 0){
          freeaddrinfo(results);
          close(sockfd);
          fprintf(stderr, "ERROR: recvfrom failed!\n");
          return EXIT_FAILURE;
        }
        else if(byte_size == 3){
          printf("%s", buf);
          return EXIT_SUCCESS;
        }
        else if(byte_size == 7){
          printf("ERROR");
          return EXIT_FAILURE;
        }
        else{
          char response[10];
          char arith[4];
          int v1, v2, result;

          if(sscanf(buf, "%3s %d %d", arith, &v1, &v2) == 3){
            printf("ASSIGNMENT: %s %d %d\n", arith, v1, v2);
          }
          else {
            fprintf(stderr, "ERROR: sscanf failed!\n");
            return EXIT_FAILURE;
          }

          if(strcmp(arith, "add") == 0){
            result = v1 + v2;
          }
          else if(strcmp(arith, "sub") == 0){
            result = v1 - v2;
          }
          else if(strcmp(arith, "mul") == 0){
            result = v1 * v2;
          }
          else if(strcmp(arith, "div") == 0){
            result = v1 / v2;
          }
          else{
            fprintf(stderr, "ERROR: invalid operation\n");
            return EXIT_FAILURE;
          }
          printf("Calculated my result to: %d\n", result);
          snprintf(response, sizeof(response), "%d\n", result);

          ssize_t sent = sendto(sockfd, response, strlen(response), 0, results->ai_addr, results->ai_addrlen);
          if(sent == -1){
            freeaddrinfo(results);
            close(sockfd);
            fprintf(stderr, "ERROR: sendto failed\n");
            return EXIT_FAILURE;
          }
        }
    }
  }

  return EXIT_SUCCESS;
}

int tcp_client(const char *host, const char *port, const char *path){
  struct addrinfo hints, *results;
  int sockfd, con;

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  int status = getaddrinfo(host, port, &hints, &results);
  if(status != 0 || results == NULL)
  {
    fprintf(stderr, "ERROR: RESOLVE ISSUE");
    return EXIT_FAILURE;
  }

  for(struct addrinfo *p = results; p != NULL; p = p->ai_next) {
    sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if(sockfd == -1) {
      continue;
    }

    con = connect(sockfd, p->ai_addr, p->ai_addrlen);
    if(con == -1) {
      close(sockfd);
      sockfd = -1;
      continue;
    }
    break;
  }

  if(sockfd == -1){
    #ifdef DEBUG 
    fprintf(stderr, "ERROR: socket failed\n");
    #endif
    return EXIT_FAILURE;
  }
  if(con == -1){
    fprintf(stderr, "ERROR: CANT CONNECT TO %s\n", host);
    freeaddrinfo(results);
    return EXIT_FAILURE;
  }

  fd_set reading;
  struct timeval timeout;
  int rc;
  
  if(strcmp(path, "binary") == 0){
    char buf[1500];
    memset(&buf, 0, sizeof(buf));
    ssize_t byte_size;

    FD_ZERO(&reading);
    FD_SET(sockfd, &reading);
    memset(&timeout, 0, sizeof(timeout));

    timeout.tv_sec = 2;
    rc = select(sockfd+1, &reading, NULL, NULL, &timeout);

    if(rc > 0){
      byte_size = read(sockfd, buf, sizeof(buf));
    }else if(rc == 0){
      freeaddrinfo(results);
      close(sockfd);
      fprintf(stderr, "ERROR: TIMEOUT\n");
      return EXIT_FAILURE;
    }else{
      perror("select");
    }    

    if(byte_size <= 0){
      freeaddrinfo(results);
      close(sockfd);
      fprintf(stderr, "ERROR: read failed!\n");
      return EXIT_FAILURE;
    }

    printf("%s", buf);

    char *line = strtok(buf, "\n");
    while(line != NULL){
      if(strcmp(line, "TEXT TCP 1.1") == 0)
        break;
      line = strtok(NULL, "\n");
    }
    if(line == NULL){
      freeaddrinfo(results);
      close(sockfd);
      fprintf(stderr, "ERROR: MISSMATCH PROTOCOL\n");
      return EXIT_FAILURE;
    }

    char tmsg[] = "BINARY TCP 1.1 OK\n";

    ssize_t sent = write(sockfd, tmsg, strlen(tmsg));
    if(sent == -1){
      freeaddrinfo(results);
      close(sockfd);
      fprintf(stderr, "ERROR: sendto failed\n");
      return EXIT_FAILURE;
    }
    printf("%s", tmsg);

    if((byte_size = read(sockfd, buf, sizeof(buf))) <= 0){
      freeaddrinfo(results);
      close(sockfd);
      fprintf(stderr, "ERROR: read failed!\n");
      return EXIT_FAILURE;
    }
    if(byte_size == sizeof(calcProtocol)){
      calcProtocol respons;
      memcpy(&respons, buf, sizeof(respons));

      uint32_t arith = ntohl(respons.arith);
      int32_t inValue1 = ntohl(respons.inValue1);
      int32_t inValue2 = ntohl(respons.inValue2);
      const char *arithText = NULL;

      switch (arith) {
        case 1: arithText = "add"; break;
        case 2: arithText = "sub"; break;
        case 3: arithText = "mul"; break;
        case 4: arithText = "div"; break;
        default: break;
      }

      int res = calc(arithText, inValue1, inValue2);

      respons.type = htons(2);
      respons.inResult = htonl(res);

      sent = write(sockfd, &respons, sizeof(respons));
      if(sent == -1){
        freeaddrinfo(results);
        close(sockfd);
        fprintf(stderr, "ERROR: sendto failed\n");
        return EXIT_FAILURE;
      }

      if((byte_size = read(sockfd, buf, sizeof(buf))) <= 0){
        freeaddrinfo(results);
        close(sockfd);
        fprintf(stderr, "ERROR: read failed!\n");
        return EXIT_FAILURE;
      }

      calcMessage r2;         
      memcpy(&r2, buf, sizeof(r2));
      uint32_t message = ntohl(r2.message);

      if(message == 1){
        printf("Server reply: OK\n");
        return EXIT_SUCCESS;
      }       
      if(message == 2){
        printf("Server reply: NOT OK\n");
        return EXIT_FAILURE;
      }  

    }

  }
  
  else if(strcmp(path, "text") == 0){
    char buf[1500];
    memset(&buf, 0, sizeof(buf));
    ssize_t byte_size;;
    
    FD_ZERO(&reading);
    FD_SET(sockfd, &reading);
    memset(&timeout, 0, sizeof(timeout));

    timeout.tv_sec = 2;
    rc = select(sockfd+1, &reading, NULL, NULL, &timeout);

    if(rc > 0){
      byte_size = read(sockfd, buf, sizeof(buf));
    }else if(rc == 0){
      freeaddrinfo(results);
      close(sockfd);
      fprintf(stderr, "ERROR: TIMEOUT\n");
      return EXIT_FAILURE;
    }else{
      perror("select");
    }  

    if(byte_size <= 0){
      freeaddrinfo(results);
      close(sockfd);
      fprintf(stderr, "ERROR: read failed!\n");
      return EXIT_FAILURE;
    }

    printf("%s", buf);

    char *line = strtok(buf, "\n");
    while(line != NULL){
      if(strcmp(line, "TEXT TCP 1.1") == 0)
        break;
      line = strtok(NULL, "\n");
    }
    if(line == NULL){
      freeaddrinfo(results);
      close(sockfd);
      fprintf(stderr, "ERROR: MISSMATCH PROTOCOL\n");
      return EXIT_FAILURE;
    }

    char tmsg[] = "TEXT TCP 1.1 OK\n";

    ssize_t sent = write(sockfd, tmsg, strlen(tmsg));
    if(sent == -1){
      freeaddrinfo(results);
      close(sockfd);
      fprintf(stderr, "ERROR: sendto failed\n");
      return EXIT_FAILURE;
    }
    printf("%s", tmsg);

    memset(&buf, 0, sizeof(buf));
    
    byte_size = read(sockfd, buf, sizeof(buf));
    if(byte_size <= 0){
      freeaddrinfo(results);
      close(sockfd);
      fprintf(stderr, "ERROR: read failed!\n");
      return EXIT_FAILURE;
    }

    char arith[4];
    int v1, v2;

    if(sscanf(buf, "%3s %d %d", arith, &v1, &v2) != 3){
      fprintf(stderr, "ERROR: sscanf failed!\n");
      return EXIT_FAILURE;
    }

    int res = calc(arith, v1, v2);
    snprintf(buf, sizeof(buf), "%d\n", res);

    sent = write(sockfd, buf, strlen(buf));
    if(sent == -1){
      freeaddrinfo(results);
      close(sockfd);
      fprintf(stderr, "ERROR: sendto failed\n");
      return EXIT_FAILURE;
    }

    memset(&buf, 0, sizeof(buf));
    
    byte_size = read(sockfd, buf, sizeof(buf));
    if(byte_size <= 0){
      freeaddrinfo(results);
      close(sockfd);
      fprintf(stderr, "ERROR: read failed!\n");
      return EXIT_FAILURE;
    }
    printf("%s", buf);

  }

  return EXIT_SUCCESS;
}

int calc(const char arith[], int v1, int v2){
  int result;


  if(strcmp(arith, "add") == 0){
    result = v1 + v2;
  }
  else if(strcmp(arith, "sub") == 0){
    result = v1 - v2;      
  }
  else if(strcmp(arith, "mul") == 0){
    result = v1 * v2;
  }
  else if(strcmp(arith, "div") == 0){
    result = v1 / v2;
  }
  else{
    fprintf(stderr, "ERROR: invalid operation\n");
  return EXIT_FAILURE;
  }

  printf("%s %d %d\n", arith, v1, v2);
  printf("Result: %d\n", result);

  return result;
}