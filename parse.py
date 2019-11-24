import dpkt, dpkt.dns
import datetime
import socket
import os 

def mac_addr(address):
	return ':'.join('%02x' % ord(b) for b in address)
	

for app in range(1,10):
	for k in range((app-1)*3+1,app*3+1):
		path = "packs/"+str(k)+".pcap"
		
		with open(path, 'rb') as f:
			pcap = dpkt.pcap.Reader(f)
			addr = []	#make addr list. 
			var = 100

			for timestamp, buf in pcap:
				eth = dpkt.ethernet.Ethernet(buf)
				ip = eth.data
				var = var - 1
				
				if var == 0:
					break
				
				if eth.type != dpkt.ethernet.ETH_TYPE_IP:
					continue
				
				if ip.p != dpkt.ip.IP_PROTO_TCP:
					continue
				
				try :
					udp = ip.data
				except : 
					continue 
				
				tmp = socket.inet_ntoa(ip.src)
				# if src ip is 10.8.0.1 -> only need dst ip. 
				if (tmp != "10.8.0.1"):
					addr.append(tmp)
				else : #else -> src ip is 10.8.0.1
					addr.append(socket.inet_ntoa(ip.dst))
		
		ex_addr = list(set(addr))
		#print ex_addr
		print "-----in file "+str(k)+"------ size : "+str(os.path.getsize(path))
		for i in ex_addr : 
			print i+ " is : " +str(addr.count(i))