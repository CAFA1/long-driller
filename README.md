<!-- TOC -->

- [INSTALL](#install)
	- [1. preinstall](#1-preinstall)
	- [2. capstone source compile](#2-capstone-source-compile)
	- [3. virtualenvwrapper](#3-virtualenvwrapper)
	- [4. claripy](#4-claripy)
	- [5. angr](#5-angr)
	- [6. shellphish-qemu](#6-shellphish-qemu)
	- [7. shellphish-afl](#7-shellphish-afl)
	- [8. tracer](#8-tracer)
	- [9. redis](#9-redis)
	- [10. fuzzer](#10-fuzzer)
	- [11. driller](#11-driller)
	- [12. binaries](#12-binaries)
- [test](#test)
	- [1. control_dependency our](#1-control_dependency-our)

<!-- /TOC -->

# INSTALL

## 1. preinstall  
	sudo apt-get install python-dev libffi-dev build-essential python-pip git  
	sudo apt-get build-dep qemu-system  
## 2. capstone source compile  
	./make.sh  
	sudo ./make.sh install  
## 3. virtualenvwrapper
	sudo apt-get install virtualenvwrapper  
	vim ~/.bashrc to add " source /usr/share/virtualenvwrapper/virtualenvwrapper.sh "  
	mkvirtualenv angr  
## 4. claripy  
	git clone https://github.com/angr/claripy.git  
	pip install -r requirements.txt  
	pip install -v -e .

## 5. angr  
	git clone https://github.com/angr/angr.git  
	pip install -r requirements.txt  
	pip install -v -e .

## 6. shellphish-qemu  
	git clone https://github.com/shellphish/shellphish-qemu.git  
	sudo apt-get install libpixman-1-dev  
	./rebuild.sh  
	pip install -v -e . 

## 7. shellphish-afl  
	git clone https://github.com/shellphish/shellphish-afl.git  
	python setup.py build  
	pip install -v -e .

## 8. tracer  
	git clone https://github.com/angr/tracer.git  
	sudo apt-get install libacl1-dev  
	pip install -r requirements.txt  
	pip install -v -e .  
 
## 9. redis  
	http://blog.fens.me/linux-redis-install/  
	sudo apt-get install redis-server  
	pip install redis  

## 10. fuzzer  
	git clone https://github.com/shellphish/fuzzer.git  
	pip install tqdm  
	pip install IPython  
	sudo apt-get install build-essential gcc-multilib libtool automake autoconf bison debootstrap debian-archive-keyring  
	sudo apt-get build-dep qemu  
	python setup.py build  
	pip install -v -e .  
## 11. driller  
	pip install -r requirements.txt  
	python setup.py build  
	pip install -v -e .  
## 12. binaries  
	git clone --depth 1 https://github.com/angr/binaries.git  

# test
## 1. control_dependency our
	cd test
	python driller_explore.py -d 1 control_flow/control_dependency