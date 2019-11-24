#!/usr/bin/env python3
#by synod2 
from collections import OrderedDict
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
		try : 
			with open(self.db_filename) as json_file:
				self.json_data = json.load(json_file)
		except :
			print("new file create")
			self.json_data = OrderedDict()
			self.json_data["appname"] = appname
			self.json_data["iplist"] = []
			self.json_data["datarate"] = 0
			self.json_data["geoIP"] = []
			
		self.iplist = self.json_data["iplist"]
		self.datarate = self.json_data["datarate"]
		self.geoIP = self.json_data["geoIP"]
			
	def save(self):
		self.json_data["iplist"] = self.iplist
		self.json_data["datarate"] = self.datarate
		self.json_data["geoIP"] = self.geoIP
		try : 
			with open(self.db_filename,'w',encoding="utf-8") as save_file:
				json.dump(self.json_data,save_file,indent="\t")
		except :
			print("save DB files")

def ipsim(old_iplist,new_iplist) :
		return len(set(old_iplist) & set(new_iplist)) / float(len(set(old_iplist) | set(new_iplist))) * 100
			
	
	
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
				
				
				print (appname+" -----in file  "+filename+"------ size : "+str(os.path.getsize(open_name)))
				print ("time:"+str(dpkt.radiotap.datarate(pcap)))
				old_db = App_db(appname)
				if(old_db.iplist != ""):
					print("ip addr similarity : "+str(round(ipsim(old_db.iplist,ex_addr),2))+"%")
			
				#old_db.iplist.append(ex_addr)
				#print ex_addr
				for i in ex_addr : 
					old_db.iplist.append(i)
				#	print (i+ " is : " +str(addr.count(i)))
				old_db.iplist = list(set(old_db.iplist))
			#	print(old_db.iplist)
				old_db.save()
				f.close()
			except : 
				print ("file open error "+open_name)
				
test = App_db("chrome")
# test.iplist.append("7.6.6.6")
# test.iplist = list(set(test.iplist))
# print(test.iplist)
# print(test.db_filename)

# test.save()