# 💻 Debian

download small image

	https://www.debian.org/distrib/


## Pre-install system ##

	Create virtual machine with virtualbox
		set name
		set machine folder
		type - linux
		version - debian 64-bit
		memory size - 1024 mb
		set create a virtual hard disk now
		file size - 30.8 G
		VDI
		Dynamically allocated

## Config virtualbox ##

	system
		Motherboard
			Base Memory - 1024 mb
			Pointing Device - PS/2 Mouse
		Processor
			2 CPUS
		Acceleration
			KVM
	display
		screen
			128mb
	network
		Bridge Adapter
			advanced
				change MAC address

## Install system ##

	Install Debian 12.2
	set english language
	set location
	set keyboard
	set hostname
	set root password
	set user password
	set installation destination
		custom
			set partitions like subject

## Set vim ##

	set vim as default editor text
		$ update-alternatives --config editor
			set /usr/bin/vim.basic

## Set sudo ##

	Install sudo
		$ apt install sudo
	Config sudo
		$ visudo
			in the end of the file add
				Defaults	badpass_message="Invalid password. No more soup for you." 
				Defaults	env_reset 
				Defaults	mail_badpass 
				Defaults	secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin”
				Defaults	passwd_tries=3
				Defaults	logfile=/var/log/sudo/sudo.log
				Defaults	log_input, log_output
				Defaults	iolog_dir="/var/log/sudo"
				Defaults	requiretty
		$ sudo mkdir -p /var/log/sudo
		$ > /var/log/sudo/sudo.log

## Upgrade system ##

	upgrade system
		$ sudo apt-get update && sudo apt-get upgrade
	install	vim
		$ sudo apt-get install net-tools bc unzip wget vim curl

## Check volumes ##

	for check volumes
		$ lsblk

## Set hostname ##

	change the hostname permanently
		$ sudo hostnamectl set-hostname 'your login'42 --static
			*--static is permanently
		or
		change the file
			/etc/hostname
		$ reboot

## Set group ##

	create a group
		$ sudo groupadd user42

	to see all group
		$ sudo getent group
		or
		$ sudo vim /etc/group

## Set rule for password ##

	install libpam
		$ sudo apt-get install libpam-pwquality
	add some rules in
		$ sudo vim /etc/pam.d/common-password
			password    requisite     pam_pwquality.so try_first_pass local_users_only retry=3 authtok_type= minlen=10 ucredit=-1 lcredit=-1 dcredit=-1 difok=7 reject_username enforce_for_root maxrepeat=3 no_difok=root
			password    sufficient    pam_unix.so remember=7
		$ sudo vim /etc/login.defs
			PASS_MAX_DAYS   30
			PASS_MIN_DAYS   2
			PASS_WARN_AGE   7
	if you have already older user, you can set the new rules with this
		$ sudo chage -M 30 'your login'
		$ sudo chage -m 2 'your login'
		$ sudo chage -W 7 'your login'

## Set user ##

	add a new user to group user42
		$ sudo usermod -aG user42 'your login'
		$ sudo usermod -aG sudo 'your login'

	for see if new user have passwd
		$ cut -d: -f1 /etc/passwd

## Set ssh ##

	install ssh
		$ sudo apt-get install openssh-server
	remove login root via ssh
		$ sudo vim /etc/ssh/sshd_config
			remove Port 22 and add Port 4242
			PermitRootLogin no
			PasswordAuthentication yes

	set ssh
		$ ssh-keygen -t rsa
	install ufw
		$ sudo apt-get install ufw
		$ sudo ufw enable
		$ sudo ufw status numbered
		$ sudo ufw delete "rule number"
		$ sudo ufw allow ssh
		$ sudo ufw allow 4242

	see what ports is open in the sshd
		$ systemctl status sshd

## Connect via ssh ##

	discover ip address
		$ hostname -I
	host terminal
		$ ssh 'your login'@'your ip' -p 4242

## Crontab files ##

	$ > /usr/local/bin/sleep.sh
		#!/bin/bash

		time=$(uptime -s | cut -d ":" -f 2)
		min=$((time%10))
		sec=$(uptime -s | cut -d ":" -f 3)

		sleep ${min}m ${sec}s

		/usr/local/bin/monitoring.sh
	$ sudo chmod 777 /usr/local/bin/sleep.sh

	$ > /usr/local/bin/monitoring.sh
		#!/bin/bash

		ARCH_HEAD=$(uname -a)
		CPU_PHYSICAL=$(grep "physical id" /proc/cpuinfo | sort | uniq | wc -l)
		VCPU=$(grep "^processor" /proc/cpuinfo | wc -l)
		FRAM=$(free -m | awk '$1 == "Mem:" {print $2}')
		URAM=$(free -m | awk '$1 == "Mem:" {print $3}')
		PRAM=$(free | awk '$1 == "Mem:" {printf("%.2f"), $3/$2*100}')
		FDISK=$(df -BG | grep '^/dev/' | grep -v '/boots$' | awk '{ft += $2} END {print ft}')
		UDISK=$(df -BM | grep '^/dev/' | grep -v '/boots$' | awk '{ut += $3} END {print ut}')
		PDISK=$(df -BM | grep '^/dev/' | grep -v '/boots$' | awk '{ut += $3} {ft+= $2} END {printf("%d"), ut/ft*100}')
		CPUL=$(vmstat 1 2 | tail -1 | awk '{printf $15}')
		CPU_OP=$(expr 100 - $CPUL)
		CPU_LOAD=$(printf "%.1f" $CPU_OP)
		LAST_BOOT=$(who -b | awk '$1 {print $3, $4}')
		LVM_STATUS=$(if [ $(lsblk | grep "lvm" | wc -l) -gt 0 ]; then echo yes; else echo no; fi)
		TCP_CONNECTIONS=$(netstat | grep ESTA | wc -l)
		USER_LOG=$(users | wc -w)
		IP=$(hostname -I)
		MAC=$(cat /sys/class/net/*/address | awk 'NR==1')
		SUDO_CMDS=$(cat /var/log/sudo/sudo.log | wc -l)

		wall <<EOF
		#Architecture: $ARCH_HEAD
		#CPU physical: $CPU_PHYSICAL
		#vCPU: $VCPU
		#Memory Usage: $URAM/${FRAM}MiB ($PRAM%)
		#Disk Usage: $UDISK/${FDISK}GB ($PDISK%)
		#CPU load: $CPU_LOAD%
		#Last boot: $LAST_BOOT
		#LVM use: $LVM_STATUS
		#Connections TCP: $TCP_CONNECTIONS ESTABLISHED
		#User log: $USER_LOG
		#Network: IP $IP ($MAC)
		#Sudo: $SUDO_CMDS cmd
		EOF
	$ sudo chmod 777 /usr/local/bin/monitoring.sh

## Crontab config ##

	$ sudo crontab -u root -e
		*/10 * * * * /usr/local/bin/sleep.sh

## Bonus - lighttpd mariadb php ##

	install lighttpd and enable service
		$ sudo apt-get install lighttpd mariadb-server php-cgi php-mysql
		$ sudo ufw allow 80
		$ cd '/var/www/'
		$ wget 'https://wordpress.org/latest.zip' -O latest.zip
		$ unzip './latest.zip'
		$ sudo rm -f './latest.zip'
		$ sudo mv './html/' './html_old/'
		$ sudo mv './wordpress/' './html/'
		$ sudo chmod -R 755 html
		$ sudo mysql_secure_installation
			Switch to unix_socket autentication? → N
			Change the root password? → N
			Remove anonymous users? → Y
			Disallow root login remotely? → Y
			Remove test database and acces to it? → Y
			Reaload privilege tables now? → Y

		$ sudo mysql -fu root << 'SQL_COMMANDS'
	DELETE FROM mysql.user WHERE User='';
	DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
	DROP DATABASE IF EXISTS test;
	DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
	FLUSH PRIVILEGES;

	CREATE DATABASE wordpress;
	CREATE USER '"your login"'@'localhost' IDENTIFIED BY 'your-password_mariadb';
	GRANT ALL PRIVILEGES ON wordpress.* TO '"your login"'@'localhost';
	FLUSH PRIVILEGES;
	SQL_COMMANDS

		$ sudo cp './wp-config-sample.php' './wp-config.php'
	
		$ sudo sed -e "s/^\s*#\?\s*define(\s*'DB_NAME',\s*.*/define('DB_NAME', 'wordpress');/" -e "s/^\s*#\?\s*define(\s*'DB_USER',\s*.*/define('DB_USER', '"your login"');/" -e "s/^\s*#\?\s*define(\s*'DB_PASSWORD',\s*.*/define('DB_PASSWORD', 'your-password_mariadb');/" -e "s/^\s*#\?\s*define(\s*'DB_HOST',\s*.*/define('DB_HOST', 'localhost');/" -i './wp-config.php'

		$ sudo grep -v 'put your unique phrase here' './wp-config.php' > tmp.php
		$ sudo curl -L 'https://api.wordpress.org/secret-key/1.1/salt' >> tmp.php
		$ sudo mv './tmp.php' './wp-config.php'
		$ sudo chown root:root './wp-config.php'
		$ sudo chmod 644 './wp-config.php'
		$ sudo lighty-enable-mod fastcgi
		$ sudo lighty-enable-mod fastcgi-php
		$ sudo service lighttpd force-reload
		$ reboot

## htop ##

	install htop
		$ sudo apt-get install htop
