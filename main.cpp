#include <iostream>
#include <math.h>
#include <string>
#include <fstream>
#include <iterator>

using namespace std;

int main(int argc, char* argv[]){	
	if(argc!=9){
		cout << "Need 8 parameters <1|0 1-encrypt 0-decrypt> <path/to/the/file> <path/to/new/file> <aes encryption scheme > <cbc|ctr|cfb ecryption mode> <path/to/keystore> <keyId> <y|n new key?>"<<endl;
	return -1;
	}
	int job = stoi(string(argv[1])); //1- encrypt, 0- decrypt
	string filePath = string(argv[2]);
	string filePath2 = string(argv[3]);
	string schemes = string(argv[4]); // AES=0
	int scheme = 0;
	if(schemes.compare("aes")==0)
		scheme = 0;
	string  modes = string(argv[5]); //CBC=0 CTR=1 CFB=2
	int mode;
	if(modes.compare("cbc")==0){
		mode = 0;
	}else if(modes.compare("ctr")==1){
		mode = 1;
	}else if(modes.compare("cfb")==2){
		mode = 2;
	}else{
		mode = 0;
	}
	string keystorePath = string(argv[6]);
	string keyId = string(argv[7]);
	string newKey = string(argv[8]);
	if(newKey.compare("y")==0){
		string c = "";
		c+= "openssl rand -base64 128 -out ";
		c+=keystorePath;
		c+="/";
		c+=keyId;
		c+= " && mcrypt -u ";
		c+=keystorePath;
		c+="/";
		c+=keyId;
		system(c.c_str());
		//cout << c <<endl;
		cout << "Key created. Working with the file now." << endl;
	}
	string jobs[] = {"-d "," "};
	string schemess[] = {"-aes-256"};
	string modess[] = {"-cbc ", "-ctr ", "-cfb "};
	string c = "";
	c+="mcrypt -d ";
	c+=keystorePath;
	c+="/";
	c+=keyId;
	c+=".nc && ";
	c+="openssl enc ";
	c+=jobs[job];
	c+=schemess[scheme];
	c+=modess[mode];
	c+="-in ";
	c+= filePath ;
	c+= " -out ";
	c+= filePath2 ;
	c+= " -pass file:"; 
	c+= keystorePath;
	c+= "/"; 
	c+= keyId;
	c+= " && rm ";
	c+=keystorePath;
	c+="/";
	c+=keyId;
	//cout << c <<endl;
	system(c.c_str());
}


