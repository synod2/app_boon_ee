#!/usr/bin/env python3
#by synod2 
from collections import OrderedDict
import geoip2.database
import dpkt, dpkt.dns
import json 
import datetime
import socket
import os 
import sys 


dirname = "packets/"
reader = geoip2.database.Reader('geoip/GeoLite2-Country.mmdb')

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
					geolist = []
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
				
				old_db = App_db(appname)
				
				for i in ex_addr : 
					response = reader.country(i)
					geolist.append(response.country.name)
				
				if(old_db.iplist != ""):
					print("ip addr similarity : "+str(round(ipsim(old_db.iplist,ex_addr),2))+"%")
					print("country similarity : "+str(round(ipsim(old_db.geoIP,geolist),2))+"%")
					
				if(round(ipsim(old_db.iplist,ex_addr),2) < 50) :
					print("----------------ip change warning! ------------")
					
				#print ex_addr
				for i in ex_addr : 
					response = reader.country(i)
					old_db.geoIP.append(response.country.name)
					old_db.iplist.append(i)
				#	print (i+ " is : " +str(addr.count(i)))

				old_db.iplist = list(set(old_db.iplist))
				old_db.geoIP = list(set(old_db.geoIP))
				#print(old_db.geoIP)
				old_db.save()
				f.close()
			except : 
				print ("file open error "+open_name)
				

#response = reader.country('128.101.101.101')
#print(response.country.name)
# test.iplist.append("7.6.6.6")
# test.iplist = list(set(test.iplist))
# print(test.iplist)
# print(test.db_filename)

# test.save()