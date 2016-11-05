#include <iostream>
#include <math.h>
#include <string>
#include <fstream>
#include <iterator>
#include "cryptopp/modes.h"
#include "cryptopp/gcm.h"
#include "cryptopp/aes.h"
#include "cryptopp/filters.h"
#include "cryptopp/base64.h"
#include "cryptopp/files.h"
#include "cryptopp/hex.h"

using namespace CryptoPP;
using namespace std;

int main(int argc, char* argv[]){	
	bool debug = true;
	if(argc!=7){
		cout << "Need 7 parameters <1|0 1-encrypt 0-decrypt> <path/to/the/file> <0 encryption scheme 0=AES> <0|1|2 ecryption mode 0=CBC 1=CTR 2=GCM> <path/to/keystore> <keyId>"<<endl;
	return -1;
	}
	int job = stoi(string(argv[1])); //1- encrypt, 0- decrypt
	string filePath = string(argv[2]);
	int scheme = stoi(string(argv[3])); // AES=0
	int mode = stoi(string(argv[4])); //CBC=0 CTR=1 GCM=2
	string keystorePath = string(argv[5]);
	int keyId = stoi(string(argv[6]));
	if(debug){
		cout << "got " << job << " " << filePath  << " " << scheme  << " " << mode  << " " << keystorePath  << " " << keyId << endl;
	}
	string str;
	const char* fp = filePath.c_str();

	ifstream ifs(fp, ios::binary|ios::in|ios::ate);
	ifs.unsetf(ios::skipws);
	streampos fileSize;
	ifs.seekg(0, ios::end);
	fileSize = ifs.tellg();
	ifs.seekg(0, ios::beg);
	vector<char> result;
	result.reserve(fileSize);
	result.insert(result.begin(), istream_iterator<char>(ifs),istream_iterator<char>());



//	FileSource file(fp, true, new StringSink(str));
//	file.PumpAll();


	const char* msg = /*str.c_str();*/&result[0];
	unsigned char iv[] = "b6948720d030e2958725ed8d22fa1416";
	unsigned char key[] = "aaaaaaaa9e43bef71df092d5500eedff02f073fd770228d1096f49d3cbdd18f";
	string encoded;
	if(scheme == 0){
		StringSink* sink = new StringSink(encoded);
		if(mode==0){
			if(job == 1){
				CBC_Mode<AES>::Encryption aes(key, sizeof(key)/2, iv);
				StreamTransformationFilter* aes_enc = new StreamTransformationFilter(aes, sink);
				StringSource source(msg, true, aes_enc);
			}else{
				CBC_Mode<AES>::Decryption aes(key, sizeof(key)/2, iv);
				StreamTransformationFilter* aes_enc = new StreamTransformationFilter(aes, sink);
				StringSource source(msg, true, aes_enc);
			}
		}else if(mode==1){
			if(job == 1){
				CTR_Mode<AES>::Encryption aes(key, sizeof(key)/2, iv);
				StreamTransformationFilter* aes_enc = new StreamTransformationFilter(aes, sink);
				StringSource source(msg, true, aes_enc);
			}else{
				CTR_Mode<AES>::Decryption aes(key, sizeof(key)/2, iv);
				StreamTransformationFilter* aes_enc = new StreamTransformationFilter(aes, sink);
				StringSource source(msg, true, aes_enc);
			}
		} else{//if(mode==2){
			if(job == 1){
				GCM<AES>::Encryption aes;
				aes.SetKeyWithIV(key, sizeof(key)/2,iv, sizeof(iv)/2);
				StringSource source(msg, true, new AuthenticatedEncryptionFilter(aes,sink));
			}else{
				GCM<AES>::Decryption aes;
				aes.SetKeyWithIV(key, sizeof(key)/2,iv, sizeof(iv)/2);
				AuthenticatedDecryptionFilter adf(aes,sink);
				StringSource source(msg, true, new Redirector(adf));
			}
		}
		cout <<"encoding: "<< msg << " decoded: " <<  encoded << endl;
	}
	
	ofstream newFile(fp, ios::binary|ios::out);
	const char* toWrite = encoded.c_str();
	newFile << toWrite;	
	//newFile.write(toWrite, sizeof(toWrite));
	newFile.close();
}


