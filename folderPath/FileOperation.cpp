#include "FileOperation.h"
#include <typeinfo> // veri türlerini kontrol etmek için kullandým þuan kullanýlmýyor
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <iomanip>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <Windows.h>

#define ETHERNET_HEADER_LENGTH 14

int FileOperation::packetCount = 0;
vector<PacketInfo> FileOperation::packets;


using namespace std;




struct ipheader {
    unsigned char      iph_ihl : 4, // IP baþlýðý uzunluðu
        iph_ver : 4; // IP versiyonu
    unsigned char      iph_tos;   // Hizmet tipi
    unsigned short int iph_len;   // Toplam uzunluk
    unsigned short int iph_ident; // Tanýmlayýcý
    unsigned short int iph_flag : 3,// Bayraklar
        iph_offset : 13; // Parça offseti
    unsigned char      iph_ttl;   // Yaþam süresi
    unsigned char      iph_protocol; // Protokol
    unsigned short int iph_chksum; // Baþlýk checksum
    struct  in_addr    iph_sourceip; // Kaynak IP adresi
    struct  in_addr    iph_destip;   // Hedef IP adresi
};

struct ethHeader {
    u_char destMac[6];
    u_char sourceMac[6];
    u_short eType; //ethernet türü
};

struct tcphdr {
    u_short th_sport;     // Kaynak port numarasý
    u_short th_dport;     // Hedef port numarasý
    uint32_t th_seq;     // Sequence number (dizi numarasý)
    uint32_t th_ack;     // Acknowledgment number (onay numarasý)
    u_char th_offx2;      // Veri ofseti, rezerve edilmiþ alanlar ve flags
    u_char th_flags;      // Kontrol flaglarý
    u_short th_win;       // Pencere boyutu
    u_short th_sum;       // Checksum
    u_short th_urp;       // Acil iþlem göstergesi
};

struct udphdr {
    u_short uh_sport;   // Kaynak port numarasý
    u_short uh_dport;   // Hedef port numarasý
    u_short uh_ulen;    // Toplam uzunluk
    u_short uh_sum;     // Checksum
};




FileOperation::FileOperation(const std::string& path) : filePath(path) {
    
    splitPath(path);
    try{
        this->handle = pcap_open_offline(this->filePath.c_str(), this->errbuf);
        if (this->handle == NULL) {
            std::cerr << "PCAP dosyasi acilamadi : " << this->errbuf << endl;
            controlOpen = false;
        }
        else {
            cout << "Basarili" << endl;
            controlOpen = true;
        }
    }
    catch (const std::exception& ex){
        cerr << "Bilinmeyen Hata :" << ex.what() << endl;
    }
}

void FileOperation::packetCapture(int loopCount){
    /*loopCount deðerine kaç verlirse o kadar paket yakalar, verilmezse sonsuz döngü içinde çalýþýr . */
    if (controlOpen != true) {
        cerr << "Hata geçerli bir pcap dosyasý seçiniz .";
    }
    else {
        cout << "Paket yakalama basliyor !! " << endl << endl << endl;
        pcap_loop(this->handle, loopCount, &FileOperation::processPacket, NULL);
        pcap_close(this->handle);
        cout << "Toplam yakalanan paket sayisi : " << packetCount << endl;
    }
    
}



void FileOperation::processPacket(u_char* user, const pcap_pkthdr* header, const u_char* pkt_data){

    struct ipheader* ip_header = (struct ipheader*)(pkt_data + ETHERNET_HEADER_LENGTH);
    struct ethHeader* eth_header = (struct ethHeader*)pkt_data;

    char source_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &(ip_header->iph_sourceip), source_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->iph_destip), dest_ip, INET_ADDRSTRLEN);
    
    stringstream sMac;
    for (int k = 0; k < 6; ++k) {
        sMac << hex << uppercase << std::setw(2) << setfill('0') << static_cast<int>(eth_header->sourceMac[k]);
        if (k < 5) {
            sMac << ":";
        }
    }

    stringstream dMac;
    for (int l = 0; l < 6; ++l) {
        dMac << hex << uppercase << std::setw(2) << setfill('0') << static_cast<int>(eth_header->destMac[l]);
        if (l < 5) {
            dMac << ":";
        }
    }
    PacketInfo pInfo;
    pInfo.sourceIP = source_ip;
    pInfo.destIP = dest_ip;
    pInfo.sourceMac = sMac.str();
    pInfo.destMac = dMac.str();


    cout << "Paket Number : " << ++packetCount << endl;
    cout << "Source IP : " << source_ip << endl;
    cout << "Source MAC : ";
    for (int k = 0; k < 6; ++k) {
        cout << hex << uppercase << static_cast<int>(eth_header->sourceMac[k]);
        if (k < 5) {
            cout << ":";
        }
    }
    cout  << endl;

    cout << "Destination IP : " << dest_ip << endl;

    cout << "Destination MAC : ";
    for (int i = 0; i < 6; ++i) {
        cout << hex << uppercase << static_cast<int>(eth_header->destMac[i]);
        if (i < 5) {
            cout << ":";
        }
    }
    cout << endl;


    if (ip_header->iph_protocol == IPPROTO_TCP) {
        struct tcphdr* tcp_header = (struct tcphdr*)(pkt_data + ETHERNET_HEADER_LENGTH + sizeof(struct ipheader));
        cout << "Source Port (TCP): " << std::dec << ntohs(tcp_header->th_sport) << endl;
        cout << "Destination Port (TCP): " << std::dec << ntohs(tcp_header->th_dport) << endl;
        pInfo.sourcePort = ntohs(tcp_header->th_sport);
        pInfo.destPort = ntohs(tcp_header->th_dport);
        pInfo.protocol = IPPROTO_TCP;

    }
    else if (ip_header->iph_protocol == IPPROTO_UDP) {
        struct udphdr* udp_header = (struct udphdr*)(pkt_data + ETHERNET_HEADER_LENGTH + sizeof(struct ipheader));
        cout << "Source Port (UDP): " << std::dec << ntohs(udp_header->uh_sport) << endl;
        cout << "Destination Port (UDP): " << std::dec << ntohs(udp_header->uh_dport) << endl;
        pInfo.sourcePort = ntohs(udp_header->uh_sport);
        pInfo.destPort = ntohs(udp_header->uh_dport);
        pInfo.protocol = IPPROTO_UDP;
    }
    cout << endl;
    packets.push_back(pInfo);

}

void FileOperation::splitPath(const string& str){
    vector<string> tokens;
    string delimiter = "\\";
    size_t start = 0, end = 0;
    while ((end = str.find(delimiter, start)) != string::npos) {
        tokens.push_back(str.substr(start, end - start));
        start = end + delimiter.length();
    }
    tokens.push_back(str.substr(start)); // Son parçayý ekle
    fileName = tokens[tokens.size() - 1];
    for (size_t i = 0; i < tokens.size()-1; i++) {
        directory += tokens[i] + delimiter ;
        
    }   
}



void FileOperation::printPacketInfo(){
    
    cout << "Paket Sayisi :" << packets.size() << endl;
    cout << "Ýlk verilen filePath :" << filePath << endl;
    cout << "Dosya Adý :" << fileName << endl;
    cout << "Dizin Adý :" << directory << endl;
    int pos = fileName.find_last_of('.');
    string ethernetTxtName = directory + fileName.substr(0, pos) + "Ethernet.txt";
    string sessionTxtName = directory + fileName.substr(0, pos) + "Session.txt";
    cout << ethernetTxtName << endl;
    cout << sessionTxtName << endl;
    
    ofstream ethernetDosya(ethernetTxtName);
    if (!ethernetDosya.is_open()) {
        std::cerr << "ethernetDosya açýlamadý!" << std::endl;
    }

    ofstream sessionDosya(sessionTxtName);
    if (!sessionDosya.is_open()) {
        std::cerr << "sessionDosya açýlamadý!" << std::endl;
    }

    for (const auto& p : packets) {
        ethernetDosya << p.sourceIP << " - " << p.sourcePort << " - " << p.destIP << " - " << p.destPort << endl;
        sessionDosya << p.sourceMac << " - " << p.destMac << endl;
    }
    
    ethernetDosya.close();
    sessionDosya.close();
}
