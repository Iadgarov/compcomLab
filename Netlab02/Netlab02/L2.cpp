/*
* Author: Tom Mahler
* Date: May 2015
*/
#include "L2.h"
#include "NIC.h"
#include "L2_ARP.h"
#include "L3.h"
//#include "L3.cpp"

#include <fstream>
#include <winsock2.h> 
#include <intrin.h>
#include <iostream>
#include <algorithm>    // std::remove_if
#include <sstream>
#include <windows.h>
#include <string>


using namespace std;


/* cool init?

Ethernet header                     28-octet ARP request/reply
|                                        |
/-----------+---------------\ /---------------------+------------------------------\
|                           |                                                       |
width in
octets:
6           6       2   2   2  1 1  2       6         4           6       4
+-----------+-----------+---+---+---+-+-+---+-----------+-------+-----------+-------+
| Ethernet  | Ethernet  |   |   |   |H|P|   |  Sender   | Sender|  Target   |Target |
|destination|  source   |FT |HT |PT |S|S|OP | Ethernet  |  IP   | Ethernet  |  IP   |
|  address  | address   |   |   |   | | |   |  Address  |Address|  Address  |Address|
+-----------+-----------+---+---+---+-+-+---+-----------+-------+-----------+-------+
^   ^   ^  ^ ^   ^
|   |   |  | |   |
|   |   |  | |   +-- Operation: 1 =  ARP request, 2 =  ARP reply
|   |   |  | |                 3 = RARP request, 4 = RARP reply
|   |   |  | |
|   |   |  |  +-- Protocol Size, number of octets
|   |   |  |     in the requested network address.
|   |   |  |     IP has 4-octet addresses, so 0x04.
|   |   |  |
|   |   |  +-- Hardware Size, number of octets in
|   |   |      the specified hardware address.
|   |   |      Ethernet has 6-octet addresses, so 0x06.
|   |   |
|   |   +-- Protocol Type, 0x0800 = IP.
|   |
|   +-- Hardware Type, Ethernet = 0x0001.
|
+-- Frame Type, 0x0806 = ARP Request or ARP Reply.
This answers "What's inside?" for the encapsulated
data within the Ethernet frame

*/

// A structure for the Ethernet header, not including ARP nonsense
struct EHeader{

	byte destAddr[6];				// 6 bytes for ethernet destination address (MAC)
	byte srcAddr[6];				// 6 bytes for ethernet source address (MAC)
	short_word frameType;				// ethernet frame type
};

string toStringMac(byte MAC[6]){
	std::string stringMAC;
	char tmp[1000];
	sprintf_s(tmp, "%02x:%02x:%02x:%02x:%02x:%02x", MAC[0], MAC[1], MAC[2], MAC[3], MAC[4], MAC[5]);
	stringMAC = std::string(tmp);
	return stringMAC;
}

void parse_mac(byte * mac, std::string macString, bool fromTable = false) {

	int temp[6];
	if (fromTable){
		sscanf(macString.c_str(), "%02x-%02x-%02x-%02x-%02x-%02x",
			&temp[0], &temp[1], &temp[2],
			&temp[3], &temp[4], &temp[5]);
	}
	else{
		sscanf(macString.c_str(), "%02x:%02x:%02x:%02x:%02x:%02x",
			&temp[0], &temp[1], &temp[2],
			&temp[3], &temp[4], &temp[5]);
	}

	for (int i = 0; i < 6; i++){
		mac[i] = (byte)temp[i];
	}
}

int whatEndianL2(){
	int num = 1;
	if (*(char *)&num == 1)
		return 0;
	return 1;
}

string IPToMAC(string ipAddr){

	string line;
	ifstream arpTable("arpTable.txt");
	string MAC = "SOMETHING WENT WRONG";

	if (arpTable.is_open())
	{
		//cout << "***********";
		size_t pos;
		while (arpTable.good())
		{
			getline(arpTable, line); // get line from file
			pos = line.find(ipAddr); // search
			line.erase(remove_if(line.begin(), line.end(), isspace), line.end());

			if (pos == string::npos) // string::npos is returned if string is not found
				continue;
			else{

				MAC = line.substr(ipAddr.length(), 17);
				break;
			}
		}
		arpTable.close();
	}
	if (MAC == "SOMETHING WENT WRONG"){
		pthread_mutex_lock(&NIC::print_mutex);
		cout << "\t\t IP Not In ARP Table! Returning MAC = IA-DG-AR-OV"; // see how I used those cool "<<" from c++? fancy.
		pthread_mutex_unlock(&NIC::print_mutex);
		return "IA-DG-AR-OV";
	}
	return MAC;
}



void printPacketL2(byte *sendMe, int len){

	int offset = len % 16 == 0 ? 0 : 1;
	int extra_space = 16 - (len % 16);

	for (int i = 0; i < len / 16 + offset; i++){

		word *line = new word[4];
		byte *p = new byte[16];
		memcpy(line, sendMe + 16 * i, 16); // take 16 bytes (full line to be printed) 
		memcpy(p, line, 16);

		if (i < len / 16){
			//printf("%08x %08x %08x %08x\t", ntohs(line[0]), line[1], line[2], line[3]);
			printf("%02x%02x%02x%02x ", p[0], p[1], p[2], p[3]);
			printf("%02x%02x%02x%02x ", p[4], p[5], p[6], p[7]);
			printf("%02x%02x%02x%02x ", p[8], p[9], p[10], p[11]);
			printf("%02x%02x%02x%02x\t", p[12], p[13], p[14], p[15]);

			for (int j = 0; j < 16; j++){
				if (isprint(*(p + j)))
					cout << (*(p + j));
				else
					cout << ".";
			}
			cout << endl;
		}
		// only gets to this else if the offset is not zero
		else {
			 
			for (int j = 0; j < 16; j++){


				if (j % 4 == 0 && j > 0)
					cout << " ";

				if (j < 16 - extra_space)
					printf("%02x", p[j]);
				else
					cout << " ";


			}
			cout << "\t";
			for (int j = 0; j < 16 - extra_space; j++){
				if (isprint(*(p + j)))
					cout << (*(p + j));
				else
					cout << ".";
			}
			cout << endl;
		}
	}

}

/**
* Implemented for you
*/
L2::L2(bool debug) : debug(debug){ }

/**
* Implemented for you
*/
void L2::setUpperInterface(L3* upperInterface){ this->upperInterface = upperInterface; }

/**
* Implemented for you
*/
void L2::setNIC(NIC* nic){ this->nic = nic; }

/**
* Implemented for you
*/
NIC* L2::getNIC(){ return nic; }

/**
* Implemented for you
*/
std::string L2::getLowestInterface(){ return nic->getLowestInterface(); }

int L2::recvFromL2(byte *recvData, size_t recvDataLen)
{
	if (debug){
		pthread_mutex_lock(&NIC::print_mutex);
		cout << "\n\n\t\t>>> recvFromL2 Started <<<\n\n"; // see how I used those cool "<<" from c++? fancy.
		pthread_mutex_unlock(&NIC::print_mutex);
	}


	//constract header from the data we got
	EHeader eHat = { 0 };
	memcpy(&eHat, recvData, 14); // header dta is the first 14 bytes 

	byte eDestAddr[6];
	for (int i = 0; i<6; i++){
		eDestAddr[i] = eHat.destAddr[i];
	}

	byte eSrcAddr[6];
	for (int i = 0; i<6; i++){
		eSrcAddr[i] = eHat.srcAddr[i];
	}

	if (recvDataLen == 0){
		pthread_mutex_lock(&NIC::print_mutex);
		cout << "recvFromL2: recvDataLen = 0, got nothing" << endl; // see how I used those cool "<<" from c++? fancy.
		pthread_mutex_unlock(&NIC::print_mutex);
		return 0;
	}

	byte* temp = new byte[6];
	parse_mac(temp, this->getNIC()->myMACAddr);

	if (toStringMac(eHat.destAddr).compare(toStringMac(temp))){
		pthread_mutex_lock(&NIC::print_mutex);
		cout << "recvFromL2: Destination MAC does not match our MAC. Dropping Packet." << endl; // see how I used those cool "<<" from c++? fancy.
		
		pthread_mutex_unlock(&NIC::print_mutex);
		return 0;
	}
	

	// before we move the data along to level 3 we want to remove the ethernet header (make sure to cancel the same removal in L3 class too)
	int fSize = recvDataLen - 14;
	byte * sendMe = new byte[fSize];
	memcpy(sendMe, recvData + 14, fSize);

	// print stuff out
	if (debug){
		pthread_mutex_lock(&NIC::print_mutex);

		printf("\nrecvFromL2: Ethernet Header At Start of The Packet sent to recvFromL2:\n\n");
		printf("\tDestination Ethernet MAC address:\t"); cout << toStringMac(eDestAddr) << endl;
		printf("\tSource Ethernet MAC addres:\t"); cout << toStringMac(eSrcAddr) << endl;
		printf("\tEthernet Frame Type:\t0x%04x\n\n", ntohs(eHat.frameType));

		cout << "recvFromL2: Data We Got from leread:" << endl;
		printPacketL2(recvData, recvDataLen);

		pthread_mutex_unlock(&NIC::print_mutex);
	}
	
	if (debug){
		pthread_mutex_lock(&NIC::print_mutex);
		cout << "\n\n\t\t>>> recvFromL2 Ended <<<\n\n"; // see how I used those cool "<<" from c++? fancy.
		pthread_mutex_unlock(&NIC::print_mutex);
	}

	upperInterface->recvFromL3(sendMe, fSize);
	return fSize;

}




int L2::sendToL2(byte *sendData, size_t sendDataLen, uint16_t family, string spec_mac, uint16_t spec_type, string dst_addr)
{

	if (debug){
		pthread_mutex_lock(&NIC::print_mutex);
		cout << "\n\n\t\t>>> sendToL2 Started <<<\n\n"; // see how I used those cool "<<" from c++? fancy.
		pthread_mutex_unlock(&NIC::print_mutex);
	}

	// got to build a header to snap onto the message L3 passes us
	EHeader eHat = { 0 };
	// we will send this:
	size_t len = sendDataLen + 14;
	byte* sendMe = new byte[len];
	memset(sendMe, 0, len);



	
	// got to make sure the destination is within the network, otherwise set to defualt gateway
	word mask = (word)inet_addr((this->getNIC()->myNetmask).c_str());
	word myIPaddr = (word)inet_addr((this->getNIC()->myIP).c_str()); // for comparison 
	word dest_ip = (word)inet_addr(dst_addr.c_str());

	if ((dest_ip & mask) != (mask & myIPaddr)){

		dst_addr = this->getNIC()->myDefaultGateway; // not in our subnet, give it the deafult gateway 

		if (debug){
			pthread_mutex_lock(&NIC::print_mutex);
			//cout << "\nsendToL2: Destination Address Not In Subnet, set to Defualt Gateway:\t" << dst_addr << endl << endl;; // see how I used those cool "<<" from c++? fancy.
			pthread_mutex_unlock(&NIC::print_mutex);
		}
	}

	// Now our destination address is set, let's turn into a MAC (even thoughe we both know PC's are better... :-P)
	spec_mac = IPToMAC(dst_addr);

	if (debug){
		pthread_mutex_lock(&NIC::print_mutex);
		cout << "\nsendToL2: Destination MAC We Got From the ARP Table:\t" << spec_mac << endl << endl; // see how I used those cool "<<" from c++? fancy.
		pthread_mutex_unlock(&NIC::print_mutex);
	}

	

	// Now we have the information and we can construct the ethernet header
	eHat.frameType = htons(spec_type);
	//parse_mac(eHat.destAddr, spec_mac, true); // turn string to MAC, true flag because of x-x-x-x form and not x:x:x:x

	int pos = 0;
	for (int i = 0; i < 6; i++) {
		sendMe[i] = stoi(spec_mac.substr(pos, 2), NULL, 16); // fill in source mac address
		pos += 3;
	}


	//parse_mac(eHat.srcAddr, this->getNIC()->myMACAddr);

	pos = 0;
	for (int i = 0; i < 6; i++) {
		sendMe[i + 6] = stoi(nic->myMACAddr.substr(pos, 2), NULL, 16); // fill in source mac address
		pos += 3;
	}

	memcpy(sendMe + 12, &eHat.frameType, 2);

	if (debug){
		pthread_mutex_lock(&NIC::print_mutex);

		printf("sendToL2: Ethernet Header Created:\n\n");
		printf("\tDestination Ethernet MAC address:\t"); cout << toStringMac(sendMe) << endl;
		printf("\tSource Ethernet MAC addres:\t"); cout << toStringMac(sendMe + 6) << endl;
		printf("\tEthernet Frame Type:\t0x%04x\n\n", ntohs(eHat.frameType));

		pthread_mutex_unlock(&NIC::print_mutex);
	}

	memcpy(sendMe + 14, sendData, sendDataLen);

	if (debug){
		pthread_mutex_lock(&NIC::print_mutex);
		cout << "\nsendToL2: Data we send to lestart:\n\n";
		printPacketL2(sendMe, len);
		cout << endl << endl;
		pthread_mutex_unlock(&NIC::print_mutex);
	}

	getNIC()->lestart(sendMe, len);

	if (debug){
		pthread_mutex_lock(&NIC::print_mutex);
		cout << "\n\n\t\t>>> sendToL2 Ended <<<\n\n"; // see how I used those cool "<<" from c++? fancy.
		pthread_mutex_unlock(&NIC::print_mutex);
	}

	return len;
}

/**
* Implemented for you
*/
L2::~L2() {}