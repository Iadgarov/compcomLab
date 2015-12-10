/*
* Author: Tom Mahler
* Date: May 2015
*/
#include "L3.h"
#include "L2.h"
#include "L4.h"
#include "NIC.h"
#include "winsock.h"
#include <iostream>
#include <cstring>
#include <string>
#include <Types.h>
#include <stdlib.h>

using namespace std;



/*
For my comfort:

0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |Type of Service|          Total Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|      Fragment Offset    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Time to Live |    Protocol   |         Header Checksum       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Source Address                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination Address                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options                    |    Padding    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

after trying arrays and all sorts of other crap, the struct came out on top:
define a structure to represent the IP header
Pay attention, this will be cool. Each field gets its own variable, from left to right.

*/



/*
L3 constructor, use it to initiate variables and data structure that you wish to use.
Should remain empty by default (if no global class variables are beeing used).
*/
L3::L3(bool debug){ this->debug = debug; }


void toStringHeader(byte *hat){

	printf("L3 HEADER CONSTRUCTED:");

	printf("\n\tVersion: 0x%x", (byte)((hat[0] & 0xF0) >> 4));
	printf("\n\tIHL: 0x%x", (int)((hat[0]) % 16));
	printf("\n\tTOS: 0x%x", hat[1]);
	printf("\n\tTotLen: 0x%x", ((hat[2] << 8) | hat[3]));
	printf("\n\tID: 0x%x", (hat[4] << 8) | hat[5]);
	printf("\n\tFlags+Offset: 0x%x", (hat[6] << 8) | hat[7]);
	printf("\n\tTTL: 0x%x", hat[8]);
	printf("\n\tProtocol: 0x%x", hat[9]);
	printf("\n\tChecksum: 0x%x", (hat[10] << 8) | hat[11]);

	word src, dst;
	src = (hat[12] << 24 | hat[13] << 16 | hat[14] << 8 | hat[15]);
	dst = (hat[16] << 24 | hat[17] << 16 | hat[18] << 8 | hat[19]);

	char temp[1024];
	byte* ptr = (byte*)&src;
	sprintf_s(temp, "%u.%u.%u.%u", ptr[3], ptr[2], ptr[1], ptr[0]);

	printf("\n\tSrc Address: 0x%08x = ", src); cout << string(temp);

	ptr = (byte*)&dst;
	sprintf_s(temp, "%u.%u.%u.%u", ptr[3], ptr[2], ptr[1], ptr[0]);
	printf("\n\tDest Address: 0x%08x = ", dst); cout << string(temp) << endl << endl;

}

void printPacketL3(byte *sendMe, int len){

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
			//cout << "**********";
			for (int j = 0; j < 16; j++){


				if (j % 4 == 0 && j > 0)
					cout << " ";

				if (j < 16 - extra_space)
					printf("%02x", p[j]);
				else
					cout << " ";


			}
			cout << "\t";
			for (int j = 0; j < 16 - extra_space ; j++){
				if (isprint(*(p + j)))
					cout << (*(p + j));
				else
					cout << ".";
			}
			cout << endl;
		}
	}
}

short_word CRC(byte *hat, int len){



	word check_sum = 0;
	int i = 0;

	for (i = 0; i < len; i += 2)
		check_sum += (hat[i] << 8) | hat[i + 1];

	while ((check_sum & 0x000f0000) != 0)
		check_sum = (check_sum >> 16) + (check_sum & 0x0000ffff);

	return (short_word)(~check_sum);


}


/*
sendToL3 is called by the upper layer via the upper layer's L3 pointer.
sendData is the pointer to the data L4 wish to send.
sendDataLen is the length of that data.
srcIP is the machines IP address that L4 supplied.
destIP is the destination IP address that L4 supplied.
debug is to enable print (use true)
*/
int L3::sendToL3(byte *sendData, size_t sendDataLen, std::string srcIP, std::string destIP)
{

	if (debug){
		pthread_mutex_lock(&NIC::print_mutex);
		cout << "\n\n\t\t>>> SendToL3 started <<<\n\n";
		pthread_mutex_unlock(&NIC::print_mutex);
	}


	byte IPHat[20] = { 0 }; //header size is 20bytes min. initiolaze the header in zeros.
	word sIP = inet_addr(srcIP.c_str()); //32 bits
	word dIP = inet_addr(destIP.c_str());//32 bits

	short_word totLen = 20 + sendDataLen; //total len= data len + header len

	IPHat[0] = (byte)((4 << 4) | 5); // IP version and length of header
	IPHat[1] = 0;
	IPHat[2] = (byte)(totLen >> 8);	// total length part 1
	IPHat[3] = (byte)(totLen & 0xff);	// total length part 2
	IPHat[4] = 0;
	IPHat[5] = 0;
	IPHat[6] = 0;
	IPHat[7] = 0;
	IPHat[8] = 255; // time to live
	IPHat[9] = 1; // ICMP

	//Source IP
	IPHat[12] = (byte)(sIP);		IPHat[13] = (byte)((sIP << 16) >> 24);
	IPHat[14] = (byte)((sIP << 8) >> 24);	IPHat[15] = (byte)(sIP >> 24);

	//Dest IP
	IPHat[16] = (byte)(dIP);	IPHat[17] = (byte)((dIP << 16) >> 24);
	IPHat[18] = (byte)((dIP << 8) >> 24);	IPHat[19] = (byte)(dIP >> 24);



	short_word Header_checksum = CRC(IPHat, 20); // calculate checksum and put in header place
	IPHat[10] = (byte)((Header_checksum & 0xff00) >> 8);
	IPHat[11] = (byte)(Header_checksum & 0x00ff);

	if (debug){
		pthread_mutex_lock(&NIC::print_mutex);
		cout << "sendToL3: IP Header Constructed::\n";
		toStringHeader(IPHat);
		pthread_mutex_unlock(&NIC::print_mutex);

	}

	byte *sendMe = new byte[totLen];
	for (int i = 0; i < totLen; i++){
		if (i < 20)
			sendMe[i] = IPHat[i];
		else
			sendMe[i] = sendData[i - 20];
	}

	if (debug){
		pthread_mutex_lock(&NIC::print_mutex);
		cout << "sendToL3: Packet We Send to sendToL2:\n";
		printPacketL3(sendMe, totLen);
		pthread_mutex_unlock(&NIC::print_mutex);

	}

	if (debug){
		pthread_mutex_lock(&NIC::print_mutex);
		cout << "\n\n\t\t>>> SendToL3 Ended <<<\n\n";
		pthread_mutex_unlock(&NIC::print_mutex);
	}


	return lowerInterface->sendToL2(sendMe, totLen, AF_INET, "", 0x0800, destIP);
}

/*
recvFromL3 is called by the upper layer via the upper layer's L3 pointer.
recvData is the pointer to the data L4 wish to receive.
recvDataLen is the length of that data.
debug is to enable print (use true)
*/
int L3::recvFromL3(byte *recvData, size_t recvDataLen)
{


	byte *IPHat = new byte[20]; // the first 20 bytes of teh header for info
	memcpy(IPHat, recvData, 20); // data should go into fields on it's own because of the way the structure is saved in memory

	
	
	{ // testing testing
		//make sure the various IP header fields are as they should be:

		// got to check that the checsum matches what we expect it to be
		short_word expectedCRC = 0;// CRC((byte *)&hat);
		if (expectedCRC != 0){
			if (debug){
				pthread_mutex_lock(&NIC::print_mutex);
				printf("recvFromL3: CRC hashcode is buggered, not zero as it should be. Instead it is: 0x%x\n", expectedCRC);
				pthread_mutex_unlock(&NIC::print_mutex);
			}
		return 0;
		}

		// is it dead?
		if (IPHat[8] == 0){
			if (debug){
				pthread_mutex_lock(&NIC::print_mutex);
				cout << "recvFromL3: TTL is zero, packet must die. Not sending jack squat to L4.\n";
				pthread_mutex_unlock(&NIC::print_mutex);
			}
		return 0;
		}

		//make sure we are using IPv4 and ICMP
		if (IPHat[9] != 1){
			if (debug){
				pthread_mutex_lock(&NIC::print_mutex);
				printf("recvFromL3: Protocl is not ICMP as expected, instead of 1 it is set to: 0x%x\n", IPHat[9]);
				pthread_mutex_unlock(&NIC::print_mutex);
			}
		return 0;
		}

		if ((byte)((IPHat[0] & 0xf0) >> 4) != 0x4){
			if (debug){
				pthread_mutex_lock(&NIC::print_mutex);
				printf("recvFromL3: IP version is not set to 0x4, what gives mate? Instead set to: 0x%x\n", (byte)((IPHat[0] & 0xf0) >> 4));
				pthread_mutex_unlock(&NIC::print_mutex);
			}
		return 0;
		}

	}// end testing testing
	

	// everything checks out, set return data to what L2 gave us minus the IP header
	// copy data without the header intot he data buffer. 20 is the min and defualt (no options) size of the IP header.

	// get data, no headers (L2 and L3)
	int size = recvDataLen - 20;// -20 for IP header
	byte * sendMe = new byte[size];
	memcpy(sendMe, recvData + 20, size);

	if (debug){
		pthread_mutex_lock(&NIC::print_mutex);
		cout << "\nrecvFromL3: Data we got from recvFromL2:\n";
		printPacketL3(recvData, recvDataLen);
		cout << "\nrecvFromL3: Data we sent to recvFromL4:\n";
		printPacketL3(sendMe, size);
		cout << endl;
		pthread_mutex_unlock(&NIC::print_mutex);
	}

	if (debug){
		pthread_mutex_lock(&NIC::print_mutex);
		cout << "\n\n\t\t>>> recvFromL3 ended <<<\n\n";
		pthread_mutex_unlock(&NIC::print_mutex);

	}

	
	return this->upperInterface->recvFromL4(sendMe, size);

}

/*
Implemented for you
*/
void L3::setLowerInterface(L2* lowerInterface){ this->lowerInterface = lowerInterface; }

/*
Implemented for you
*/
void L3::setUpperInterface(L4* upperInterface){ this->upperInterface = upperInterface; }

/*
Implemented for you
*/
std::string L3::getLowestInterface(){ return lowerInterface->getLowestInterface(); }


