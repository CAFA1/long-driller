# Install
1. preinstall  
	sudo apt-get install python-dev libffi-dev build-essential python-pip git  
	sudo apt-get build-dep qemu-system  
2. capstone source compile  
./make.sh  
sudo ./make.sh install  
3. virtualenvwrapper
sudo apt-get install virtualenvwrapper  
vim ~/.bashrc to add " source /usr/share/virtualenvwrapper/virtualenvwrapper.sh "  
mkvirtualenv angr  
4. claripy  
git clone https://github.com/angr/claripy.git  
pip install -r requirements.txt  
pip install -v -e .
5. shellphish-qemu  
git clone https://github.com/shellphish/shellphish-qemu.git  
sudo apt-get install libpixman-1-dev  
./rebuild.sh  
python setup.py install  
6. tracer  
git clone https://github.com/angr/tracer.git  
sudo apt-get install libacl1-dev  
python setup.py install  
6. cle
https://github.com/angr/cle.git  
python setup.py install  
7. angr  
git clone https://github.com/angr/angr.git  
python setup.py install  
8. redis  
http://blog.fens.me/linux-redis-install/  
sudo apt-get install redis-server  
sudo pip install redis  
9. celery  
git clone --depth=1 https://github.com/celery/celery.git
python setup.py install  
10. archinfo  
git clone --depth=1 https://github.com/angr/archinfo.git  
python setup.py install  
11. termcolor  
pip install termcolor  
12. shellphish-afl  
git clone https://github.com/shellphish/shellphish-afl.git  
python setup.py build  
pip install -v -e .
13. fuzzer  
git clone https://github.com/shellphish/fuzzer.git  
pip install tqdm  
pip install IPython  
sudo apt-get install build-essential gcc-multilib libtool automake autoconf bison debootstrap debian-archive-keyring  
sudo apt-get build-dep qemu  
python setup.py build  
pip install -v -e .  
14. driller  
pip install -r requirements.txt  
python setup.py build  
pip install -v -e .  
15. binaries  
git clone --depth 1 https://github.com/angr/binaries.git  