import dpkt
import datetime
import socket
import matplotlib.pyplot as plt
import sys
import numpy as np
from dpkt.compat import compat_ord

#declared lists
timeList = []
portDestList = []
#passing args to variables for later
specIP = sys.argv[2]
specFile = sys.argv[1]

def main():

	#get file name passed from 1st argument
	file_name = sys.argv[1]
	#get ip passed from 2nd argument
	setIP = sys.argv[2]
	#open file in read bytes, pass as f
	with open(file_name, 'rb') as f:
		#read pcap using module
		pcap = dpkt.pcap.Reader(f)
		#call extract function with arguments
		extract(pcap, setIP)
	#call graph function
	plot()

#the next 12 lines are adapted from https://dpkt.readthedocs.io/en/latest/_modules/examples/print_http_requests.html#mac_addr
def mac_add(address):

	#convert mac address in hex to readable format
	return ':'.join('%02x' % compat_ord(b) for b in address)

#the next 7 lines are adapted from https://dpkt.readthedocs.io/en/latest/_modules/examples/print_http_requests.html#inet_to_str
def convert(inet):
   	
	#convert hex to readable format
	try:
		return socket.inet_ntop(socket.AF_INET, inet)
	except ValueError:
		return socket.inet_ntop(socket.AF_INET6, inet)

def extract(pcap, setIP):
	
	#counter set to 0
	packetCounter = 0

	#create txt file in write mode
	with open('out.txt', 'w') as O:
		#the next 4 lines are adapted from https://jon.oberheide.org/blog/2008/10/15/dpkt-tutorial-2-parsing-a-pcap-file/
		#for each timestamp in pcap
		for timestamp, buf in pcap:
			#extract ethernet frame
			eth = dpkt.ethernet.Ethernet(buf)

			#the next 11 lines are adapted from https://dpkt.readthedocs.io/en/latest/_modules/examples/print_http_requests.html#inet_to_str
			#if none IP frame found
			if not isinstance(eth.data, dpkt.ip.IP):
				continue

			#take data from ethernet frame
			ip = eth.data

			#if TCP packet found
			if isinstance(ip.data, dpkt.tcp.TCP):
			#pass data to object
				tcp = ip.data
				#if source ip matches argument ip
				if convert(ip.src) == setIP:
					# the next 8 lines are adapted from https://dpkt.readthedocs.io/en/latest/_modules/examples/print_http_requests.html#inet_to_str
					#write timestamp to file
					print >> O, 'Timestamp: ', str(datetime.datetime.utcfromtimestamp(timestamp))
					#write MAC source to dest to file
					print >> O, 'MAC: %s ---> %s %s' % (mac_add(eth.src), mac_add(eth.dst), eth.type)
					#write IP source to dest in readable format to file
					print >> O, 'IP: %s ---> %s' % (convert(ip.src), convert(ip.dst))
					#write port source to dest to file
					print >> O, 'Port: %s ---> %d \n' % (tcp.sport, tcp.dport)

					#add timestamp to list
					timeList.append(datetime.datetime.utcfromtimestamp(timestamp))
					#add port dest to list
					portDestList.append(tcp.dport)
					#every packet found increment by 1
					packetCounter +=1

		#convert to string
		z = str(packetCounter)
		O.write('Total number of packets found ' + z)
		#close file
		O.close

def plot():

	#GRAPH DESTINATION PORT AGAINST THE TIME STAMP OF THE PACKETS
	#the next 10 lines are adapted from https://matplotlib.org/examples/pylab_examples/simple_plot.html
	#size window
	plt.figure(figsize=(10,5))
	#label axis
	plt.xlabel('TIMESTAMP')
	plt.ylabel('DESTINATION PORT')
	#plot lists
	plt.plot(timeList,portDestList, 'ro', markersize=0.5)
	plt.title('Displaying packets from source IP ' + specIP + ' within file ' + specFile)
	plt.suptitle('TCP data')
	plt.show()

main()
