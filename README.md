### Setup
#### mininet
```
git clone https://github.com/mininet/mininet
cd mininet
sudo ./util/install.sh -n3v
```
#### ryu
```
sudo pip install ryu
```
#### torch
```
sudo pip install torch
```
#### scapy and dpkt
```
sudo pip install scapy
sudo pip install dpkt
```
#### django
```
sudo pip install django
```
#### others
```
sudo apt install net-tools              # for ifconfig
```
### Install
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
