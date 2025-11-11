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
    //初始化ssl
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    SSL_CTX *ctx=SSL_CTX_new(TLS_server_method());
    char path_key[256],path_crt[256];
    const char *home = getenv("HOME");  // 获取用户主目录
    snprintf(path_key, sizeof(path_key), "%s/.ca/server.key", home);
    snprintf(path_crt, sizeof(path_crt), "%s/.ca/server.crt", home);
    int SSL_CA_FLAG=SSL_CTX_use_certificate_file(ctx,path_crt,SSL_FILETYPE_PEM);
    if(SSL_CA_FLAG<0){printf("ca load err");}
    int SSL_Pri_key_FLAG=SSL_CTX_use_PrivateKey_file(ctx,path_key,SSL_FILETYPE_PEM);
    if(SSL_Pri_key_FLAG<0){printf("Pri key load err");}
    SSL_CTX_check_private_key(ctx);
    SSL* ssl=SSL_new(ctx);
    #endif
    int fd=socket(AF_INET6,SOCK_STREAM,IPPROTO_TCP);
    if(fd<0){
        printf("socket setup err\n");
        return;
    }
    int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    int off = 0;
    setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off));  // 允许 IPv4/IPv6 共用

    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(12345);
    addr.sin6_addr = in6addr_loopback;  // localhost (IPv4 127.0.0.1 也可连接)

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
        return;
    }
    #ifdef SSL_OPEN
    //绑定到接收套接字  
    SSL_set_fd(ssl, accpt);  
    if (SSL_accept(ssl) <= 0) {
    ERR_print_errors_fp(stderr);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(fd);
    return;
    }
    #endif
    printf("accepted\n");
    char buff[2048];
    char exit[]="exit";
    while(1)
    {    
    memset(buff,0,2048);
    #ifdef SSL_OPEN
    //ssl解密
    int res=SSL_read(ssl,buff,2048);
    #else
    int res=recv(accpt,buff,2048,0);
    #endif
    if(res <= 0) {printf("no recv err");break;}
    if(res>=4)if(!memcmp(buff,exit,4))break;
    FILE *f = fopen("./end.txt", "a+b");
    if(f) {
        fwrite(buff, 1, res, f);
        fclose(f);
    }
    for(int i=0;i<res;i++){printf("%c",buff[i]);}
    #ifdef SSL_OPEN
    SSL_write(ssl,buff,res);
    #else
    send(accpt,buff,res,0);
    #endif
    }
    close(fd);
    close(accpt);
    #ifdef SSL_OPEN
    //关闭ssl
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