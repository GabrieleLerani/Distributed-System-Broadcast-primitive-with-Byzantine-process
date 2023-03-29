import prova
import asyncore

if __name__=="__main__":
   s=prova.tcp_rx("ciao","localhost",8080)
   s2=prova.tcp_rx("ciao2","localhost",8082)
   s.run()
   s2.run()