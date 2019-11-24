#!/usr/bin/env python3
#by synod2 
import dpkt, dpkt.dns
import json 
import datetime
import socket
import os 
import sys 

dirname = "packets/"

class App_db:
	def __init__(self,appname):
		self.db_filename = dirname+appname+"/"+appname+".json"
		with open(self.db_filename) as json_file:
			self.json_data = json.load(json_file)
			self.iplist = self.json_data["iplist"]
			
	def save(self):
		with open(self.db_filename,'w',encoding="utf-8") as save_file:
			json.dump(self.json_data,save_file,indent="\t")
		
for (path,dir,files) in os.walk(dirname) :
	for filename in files :
		ext = os.path.splitext(filename)[-1]
		if ext == '.pcap':
			appname = path.replace(dirname,"")
			open_name = path+"/"+filename
			
			try : 
				with open(open_name,'rb') as f:
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
				#ex_addr -> lists of Not duplicated address.
				ex_addr = list(set(addr))
				
				#print ex_addr
				print (appname+" -----in file  "+filename+"------ size : "+str(os.path.getsize(path)))
				for i in ex_addr : 
					print (i+ " is : " +str(addr.count(i)))
				
			
			except : 
				print ("file open error "+open_name)
				
				
# test = App_db("example")
# test.iplist.append("6.6.6.6")
# print(test.iplist)
# print(test.db_filename)

# test.save()