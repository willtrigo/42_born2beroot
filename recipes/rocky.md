# 💻 Rocky Linux

download minimal

	https://rockylinux.org/download


## Pre-install system ##

	Create virtual machine with virtualbox
		set name
		set machine folder
		type - linux
		version - red hat 64-bit
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

	Install Rocky Linux 9.2
	set english language
	set keyboard
	set software selection
		minimal install
		guest agents
	set root password
	set installation destination
		custom
			set partitions like subject
	set KDUMP

## Upgrade system ##

	upgrade system
		$ sudo dnf upgrade --refresh --setopt fastestmirror=1
	install	vim
		$ sudo dnf install net-tools bc unzip wget

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

## Set sudo ##

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

## Set group ##

	create a group
		$ sudo groupadd user42

	to see all group
		$ sudo getent group
		or
		$ sudo vi /etc/group

## Set rule for password ##

	add some rules in
		$ sudo vi /etc/pam.d/system-auth
			password    requisite     pam_pwquality.so try_first_pass local_users_only retry=3 authtok_type= minlen=10 ucredit=-1 lcredit=-1 dcredit=-1 difok=7 reject_username enforce_for_root maxrepeat=3 no_difok=root
			password    sufficient    pam_unix.so remember=7
		$ sudo vi /etc/pam.d/password-auth
			password    requisite     pam_pwquality.so try_first_pass local_users_only retry=3 authtok_type= minlen=10 ucredit=-1 lcredit=-1 dcredit=-1 difok=7 reject_username enforce_for_root maxrepeat=3 no_difok=root
			password    sufficient    pam_unix.so remember=7
		$ sudo vi /etc/login.defs
			PASS_MAX_DAYS   30
			PASS_MIN_DAYS   2
			PASS_WARN_AGE   7
	if you have already older user, you can set the new rules with this
		$ sudo chage -M 30 'your login'
		$ sudo chage -m 2 'your login'
		$ sudo chage -W 7 'your login'

## Set user ##

	create a new user
		$ sudo useradd 'your login'
		$ sudo passwd 'your login'

	add a new user to group
		$ sudo usermod -aG wheel 'your login'
			*add in the group wheel is good for this user get root privilegies.
		$ sudo usermod -aG user42 'your login'

	for see if new user have passwd
		$ cut -d: -f1 /etc/passwd

## Set ssh ##

	remove login root via ssh
		$ sudo vi /etc/ssh/sshd_config
			remove Port 22 and add Port 4242
			PermitRootLogin no
			PasswordAuthentication yes

	set ssh
		$ ssh-keygen -t rsa
		$ sudo firewall-cmd --add-port=4242/tcp --permanent
		$ sudo dnf install policycoreutils-python-utils
		$ sudo semanage port -a -t ssh_port_t -p tcp 4242

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

		ARCH_HEAD=$(uname -sn)
		ARCH_NAME="Rocky"
		ARCH_MID=$(uname -r)
		ARCH_MONTH=$(uname -v | sed 's/^//' | cut -d' ' -f5 | awk 'BEGIN{months="JanFebMarAprMayJunJulAugSepOctNovDec"} {printf("%02d"), (index(months,$0)/3)}')
		ARCH_DAY=$(uname -v | sed 's/^//' | cut -d' ' -f6)
		ARCH_YEAR=$(uname -v | sed 's/^//' | cut -d' ' -f9)
		ARCH_TAIL=$(uname -io)
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
		#Architecture: $ARCH_HEAD $ARCH_NAME $ARCH_MID ($ARCH_YEAR-$ARCH_MONTH-$ARCH_DAY) $ARCH_TAIL
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

	upgrade system
		$ sudo dnf upgrade --refresh --setopt fastestmirror=1
	install lighttpd and enable service
		$ sudo dnf install epel-release
		$ sudo dnf install lighttpd lighttpd-fastcgi mariadb mariadb-server php php-mysqlnd php-fpm php-gd php-xml php-mbstring
		$ sudo systemctl enable --now lighttpd mariadb php-fpm
		$ sudo printf '\ninclude "conf.d/fastcgi.conf"\n' >> '/etc/lighttpd/lighttpd.conf'
		$ sudo sed -e 's/^\s*#\?\s*server.use-ipv6\s*=.*/server.use-ipv6 = "disable"/' -i '/etc/lighttpd/lighttpd.conf'

		$ sudo cat << FASTCGI_CONF >> '/etc/lighttpd/lighttpd.conf'

	fastcgi.server += ( ".php" =>
		((
			"host" => "127.0.0.1",
			"port" => "9000",
			"broken-scriptfilename" => "enable"
		))
	)
	FASTCGI_CONF

		$ sudo chown lighttpd:lighttpd /var/log/lighttpd/access.log
		$ sudo chmod 644 /var/log/lighttpd/access.log
		$ sudo chown lighttpd:lighttpd /var/log/lighttpd/error.log
		$ sudo chmod 644 /var/log/lighttpd/error.log
		$ sudo chmod 755 /var/log/lighttpd

		$ sudo sed -e 's/^\s*#\?\s*user\s*=\s*.*/user = lighttpd/' \
	-e 's/^\s*#\?\s*group\s*=\s*.*/group = lighttpd/' \
	-e 's/^\s*#\?\s*listen\s*=\s*.*/listen = 127.0.0.1:9000/' \
	-e 's/^\s*#\?\s*listen.owner\s*=\s*.*/listen.owner = lighttpd/' \
	-e 's/^\s*#\?\s*listen.group\s*=\s*.*/listen.group = lighttpd/' \
	-e 's/^\s*#\?\s*listen.mode\s*=\s*.*/listen.mode = 0660/' \
	-i \
	'/etc/php-fpm.d/www.conf'

		$ sudo setsebool -P httpd_setrlimit on
		$ sudo setsebool -P httpd_can_network_connect 1
		$ sudo systemctl restart lighttpd php-fpm
		$ cd '/tmp'
		$ wget 'https://wordpress.org/latest.zip' -O latest.zip
		$ unzip './latest.zip'
		$ sudo rm -f './latest.zip'
		$ mv './wordpress' '/var/www/lighttpd'
		$ sudo chown -R lighttpd:lighttpd '/var/www/lighttpd/wordpress'
		$ sudo find '/var/www/lighttpd/wordpress' -type d -exec chmod 775 {} \;
		$ sudo find '/var/www/lighttpd/wordpress' -type f -exec chmod 644 {} \;
		$ cd -P '/var/www/lighttpd/wordpress'
		$ sudo cp './wp-config-sample.php' './wp-config.php'

		$ sudo sed -e "s/^\s*#\?\s*define(\s*'DB_NAME',\s*.*/define('DB_NAME', 'wordpress');/" -e "s/^\s*#\?\s*define(\s*'DB_USER',\s*.*/define('DB_USER', '"your login"');/" -e "s/^\s*#\?\s*define(\s*'DB_PASSWORD',\s*.*/define('DB_PASSWORD', 'your-password_mariadb');/" -e "s/^\s*#\?\s*define(\s*'DB_HOST',\s*.*/define('DB_HOST', 'localhost');/" -i './wp-config.php'

		$ sudo grep -v 'put your unique phrase here' './wp-config.php' > tmp.php
		$ sudo curl -L 'https://api.wordpress.org/secret-key/1.1/salt' >> tmp.php
		$ sudo mv './tmp.php' './wp-config.php'
		$ sudo chown lighttpd:lighttpd './wp-config.php'
		$ sudo chmod 644 './wp-config.php'
		$ sudo firewall-offline-cmd --add-service=http
		$ sudo firewall-offline-cmd --add-service=https
		$ sudo chcon -R -t httpd_sys_content_t /var/www/lighttpd/wordpress
		$ sudo systemctl restart lighttpd

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

		$ reboot

## htop ##

	install htop
		$ sudo dnf install htop
