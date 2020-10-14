### Setup Environment
#### 1. Install mininet
```
git clone https://github.com/mininet/mininet
cd mininet
sudo ./util/install.sh -s /path/you/want -n3v
```
#### 2. Install ryu
```
sudo pip install ryu
```
#### 3. Install torch
```
sudo pip install torch
```
#### 4. Install scapy and dpkt
```
sudo pip install scapy
sudo pip install dpkt
```
#### 5. Install django
```
sudo pip install django
```
#### 6. Other dependencies
```
sudo apt install net-tools              # for ifconfig
```
### Install SDN-Firewall
```
git clone --recursive https://github.com/GuArDiL/SDN-Firewall.git
git clone https://github.com/GuArDiL/web_admin.git
```
or
```
git clone https://github.com/GuArDiL/SDN-Firewall.git
git clone https://github.com/GuArDiL/web_admin.git
cd SDN-Firewall
git submodule update --init
```
### Run
```
cd SDN-Firewall/test
./run.sh firewall       # in tty 1
./run.sh mininet        # in tty 2
./run.sh ids            # in tty 3
```
then interact with mininet in tty 2
```
h2 ./run.sh test1
h2 ./run.sh test2
```
or run test from web_admin
```
./run.sh admin          # also in SDN-Firewall/test
```
then access port 8192 at 127.0.0.1 (or any other available IP in your machine)
