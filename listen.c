#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#ifdef SSL_OPEN
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#endif
void this_socket(){
    #ifdef SSL_OPEN
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    SSL_CTX *ctx=SSL_CTX_new(TLS_server_method());
    char path_key[32],path_crt[32];
    const char *home = getenv("HOME");  // 获取用户主目录
    snprintf(path_key, sizeof(path_key), "%s/.ca/server.key", home);
    snprintf(path_crt, sizeof(path_crt), "%s/.ca/server.crt", home);
    SSL_CTX_use_certificate_file(ctx,path_crt,SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx,path_key,SSL_FILETYPE_PEM);
    SSL_CTX_check_private_key(ctx);
    SSL* ssl=SSL_new(ctx);
    #endif
    int fd=socket(AF_INET6,SOCK_STREAM,IPPROTO_TCP);
    if(fd<0){
        printf("socket setup err\n");
        return;
    }
    struct sockaddr_in6 addr;
    memset(&addr,0,sizeof(addr));//<string.h>
    addr.sin6_family=AF_INET6;
    addr.sin6_port=htons(12345);
    inet_pton(AF_INET6,"::1",&addr.sin6_addr);
    int bin=bind(fd,(struct sockaddr*)&addr,sizeof(addr));/*<arpa/inet.h>*/
    if(bin<0){
        printf("bind err\n");
        close(fd);
        return;
    }
    int lisn=listen(fd,5);
    if(lisn<0){
        printf("listen err\n");
        close(fd);
        return;
    }
    printf("listening\n");
    struct sockaddr_in6 cliaddr;
    memset(&cliaddr,0,sizeof(cliaddr));
    socklen_t cliaddr_len=sizeof(cliaddr);
    int accpt=accept(fd,(struct sockaddr*)&cliaddr,&cliaddr_len);
    if(accpt<0){
        printf("accept err\n");
        close(fd);
        close(accpt);
        return;
    }
    #ifdef SSL_OPEN
    SSL_set_fd(ssl, accpt);  
    if (SSL_accept(ssl) <= 0) {
    ERR_print_errors_fp(stderr);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(accpt);
    close(fd);
    return;
    }
    #endif
    printf("accepted\n");
    char buff[2048];
    while(1)
    {    
    memset(buff,0,2048);
    recv(accpt,buff,2048,0);
    char exit[]="exit";
    if(!memcmp(buff,exit,4))break;
    #ifdef SSL_OPEN
    SSL_read(ssl,buff,2048);
    #endif
    for(int i=0;i<2048;i++){printf("%c",buff[i]);}
    #ifdef SSL_OPEN
    SSL_write(ssl,buff,2048);
    #endif
    send(accpt,buff,2048,0);
    }
    close(fd);
    close(accpt);
    #ifdef SSL_OPEN
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    #endif
}



int _main(){
    this_socket();
    return 0;
}


int main(){
    return _main();

}