#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>

static std::string now() {
  using namespace std::chrono;
  auto t = system_clock::to_time_t(system_clock::now());
  char buf[32];
  strftime(buf, sizeof(buf), "%F %T", std::localtime(&t));
  return buf;
}
static int set_nonblock(int fd){int fl=fcntl(fd,F_GETFL,0); if(fl<0)return -1; return fcntl(fd,F_SETFL,fl|O_NONBLOCK);}

struct Conn{int fd; std::string inbuf; std::deque<std::string> outq; std::string peer;};

int main(int argc,char* argv[]){
  if(argc!=2){std::cerr<<"Usage: tsamgroup21 <port>\n"; return 1;}
  const char* MY_GROUP="A5 21";
  int port=std::atoi(argv[1]);

  int ls=socket(AF_INET,SOCK_STREAM,0); if(ls<0){perror("socket");return 1;}
  int on=1; setsockopt(ls,SOL_SOCKET,SO_REUSEADDR,&on,sizeof(on));
  if(set_nonblock(ls)<0){perror("fcntl");return 1;}

  sockaddr_in addr{}; addr.sin_family=AF_INET; addr.sin_addr.s_addr=INADDR_ANY; addr.sin_port=htons(port);
  if(bind(ls,(sockaddr*)&addr,sizeof(addr))<0){perror("bind"); return 1;}
  if(listen(ls,16)<0){perror("listen"); return 1;}
  std::cout<<now()<<" SERVER listening on port "<<port<<"\n";

  std::unordered_map<int,Conn> conns;
  std::deque<std::string> inbox;

  auto enqueue=[&](Conn& c,const std::string& line){ c.outq.push_back(line+"\n"); };

  while(true){
    std::vector<pollfd> pfds; pfds.push_back({ls,POLLIN,0});
    for(auto& [fd,c]:conns){short ev=POLLIN; if(!c.outq.empty()) ev|=POLLOUT; pfds.push_back({fd,ev,0});}
    int rc=poll(pfds.data(),pfds.size(),1000); if(rc<0){perror("poll"); break;}

    if(pfds[0].revents&POLLIN){
      sockaddr_in cli{}; socklen_t cl=sizeof(cli);
      while(true){
        int fd=accept(ls,(sockaddr*)&cli,&cl);
        if(fd<0){ if(errno==EAGAIN||errno==EWOULDBLOCK) break; perror("accept"); break; }
        set_nonblock(fd);
        char ip[INET_ADDRSTRLEN]; inet_ntop(AF_INET,&cli.sin_addr,ip,sizeof(ip));
        int cport=ntohs(cli.sin_port);
        Conn c{fd,{},{} , std::string(ip)+":"+std::to_string(cport)};
        conns.emplace(fd,std::move(c));
        std::cout<<now()<<" ACCEPT "<<ip<<":"<<cport<<" fd="<<fd<<"\n";
      }
    }

    for(size_t i=1;i<pfds.size();++i){
      int fd=pfds[i].fd;
      auto it=conns.find(fd); if(it==conns.end()) continue;
      Conn& c=it->second;

      if(pfds[i].revents&(POLLIN|POLLERR|POLLHUP)){
        char buf[4096];
        while(true){
          ssize_t n=recv(fd,buf,sizeof(buf),0);
          if(n>0){ c.inbuf.append(buf,buf+n); }
          else if(n==0){ std::cout<<now()<<" CLOSE "<<c.peer<<" fd="<<fd<<"\n"; close(fd); conns.erase(it); goto next_fd; }
          else { if(errno==EAGAIN||errno==EWOULDBLOCK) break; perror("recv"); close(fd); conns.erase(it); goto next_fd; }
        }
        size_t pos;
        while((pos=c.inbuf.find('\n'))!=std::string::npos){
          std::string line=c.inbuf.substr(0,pos); c.inbuf.erase(0,pos+1);
          if(!line.empty() && line.back()=='\r') line.pop_back();
          std::cout<<now()<<" RX "<<c.peer<<" \""<<line<<"\"\n";

          if(line=="LISTSERVERS"){
            // Return just ourselves for early-bonus demo
            enqueue(c,std::string("SERVERS,")+MY_GROUP+",127.0.0.1,"+std::to_string(port));
          } else if(line.rfind("SENDMSG,",0)==0){
            // SENDMSG,GROUPID,<text>
            size_t p1=line.find(',',7);
            if(p1!=std::string::npos){
              size_t p2=line.find(',',p1+1);
              if(p2!=std::string::npos){
                std::string to=line.substr(p1+1,p2-(p1+1));
                std::string text=line.substr(p2+1);
                if(to==MY_GROUP) inbox.push_back(text);
                enqueue(c,"OK");
              } else enqueue(c,"ERR,BADFORMAT");
            } else enqueue(c,"ERR,BADFORMAT");
          } else if(line=="GETMSG"){
            if(!inbox.empty()){ std::string msg=inbox.front(); inbox.pop_front(); enqueue(c,std::string("MSG,")+msg); }
            else enqueue(c,"EMPTY");
          } else {
            enqueue(c,"ERR,UNKNOWN");
          }
        }
      }

      if(pfds[i].revents&POLLOUT){
        while(!c.outq.empty()){
          const std::string& front=c.outq.front();
          ssize_t n=send(fd,front.data(),front.size(),0);
          if(n<0){
            if(errno==EAGAIN||errno==EWOULDBLOCK) break;
            perror("send"); close(fd); conns.erase(it); goto next_fd;
          }
          if((size_t)n<front.size()){ c.outq.front()=front.substr(n); break; }
          else { std::string sent=front; std::string log=sent; if(!log.empty()&&log.back()=='\n') log.pop_back();
                 std::cout<<now()<<" TX "<<c.peer<<" \""<<log<<"\"\n"; c.outq.pop_front(); }
        }
      }
      next_fd: continue;
    }
  }
}