import scapy.all as scapy
import argparse

def ger_arguments():
    parser=argparse.ArgumentParser()
    parser.add_argument('-t','--target',dest='target',help='Target IP / IP range.')
    (options)=parser.parse_args()
    return options




def scan(ip):
    arp_request=scapy.ARP(pdst=ip)
    broadcast=scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_broadcast=broadcast/arp_request
    ans=scapy.srp(arp_request_broadcast,timeout=1,verbose=False)[0]


    lists=[]

    for element in ans :
         dicts={'ip':element[1].psrc,'mac':element[1].hwsrc}
         lists.append(dicts)


    return lists

def result(print_result):
    print('IP\t\t\t\tMAC \n-----------------------------------------')
    for client in print_result:

        print(client['ip']+'\t\t'+client['mac'])





options=ger_arguments()
scan_result=scan(options.target)
result(scan_result)
