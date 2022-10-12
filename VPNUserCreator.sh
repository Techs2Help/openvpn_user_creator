#!/bin/bash
CONFIG_DIR="<path>"
CONFIG_DIR_OVPN="<path>"
HOME_FOLDERS_DIR="<path>"

ADMIN_EMAIL=""
PASSWORD_LENGTH=16

GROUP_A=1
GROUP_B=2

# check that all components needed are present
if [ "$USER" != "root" ]; then echo "Please run this script as sudo"; exit 1; fi

if [[ ! -d $CONFIG_DIR ]]; then
	echo "Directory $CONFIG_DIR not found"
	exit 127
else
	cd $CONFIG_DIR
fi

GOOGLE_AUTH=$(which google-authenticator)
if [[ -z $GOOGLE_AUTH ]]; then echo "Google Authenticator command cannot be found"; exit 127; fi

QRENCODE=$(which qrencode)
if [[ -z $QRENCODE ]]; then echo "QREncode command command cannot be found"; exit 127; fi

OPENSSL=$(which openssl)
if [[ -z $OPENSSL ]]; then echo "Openssl command cannot be found"; exit 127; fi

EASYRSA="<path>"
if ! [ -f $EASYRSA ]; then echo "Easyrsa command connot be found"; exit 127; fi

#print the usage menu
function usage(){
	echo "sudo ./VPNUserCreator.sh {options}"
	echo "	-h: show usage"
	echo "	-c: create a user, requires -u and -g option"
	echo "	-d: delete user, requires -u option"
	echo "	-r: reset user password, requires -u option"
	echo
	echo "	-u <user>: specify username, username can only contains letters, '_' and '.', if whitespace is present, only the first part is taken"
	echo "	-g <group>: specify username's group"
	exit 1
}

# function to check if user is present in the linux server database
function isUserValid(){
	username=$1

	isPresent="FALSE"
	if $($(which id) "$username" &>/dev/null); then
		isPresent="TRUE"
	fi

	echo $isPresent
}

# function to set a random password to username and set it to never expire
function setUserPassword(){
	USERNAME=$1
	PASSWORD=$(echo $($OPENSSL rand -base64 48 | $(which cut) -c1-$PASSWORD_LENGTH))
	echo "password: $PASSWORD" >> $HOME_FOLDERS_DIR$username"/user_information.txt"

	echo ${USERNAME}":"${PASSWORD} | chpasswd
}

# function to create user multifactor authentication QR Code
function create2FA(){
	username=$1

	$($GOOGLE_AUTH -t -d -f -r 3 -R 30 -W -q -s $(echo $CONFIG_DIR"google-auth/"$username))
	secret=$(head -n 1 $(echo $CONFIG_DIR"google-auth/"$username))
	$($QRENCODE -t PNG -o $(echo $HOME_FOLDERS_DIR$username"/qr.png") $(echo "otpauth://totp/"$username"@vpn?secret="$secret"&issuer=openvpn"))

	echo "2FA secret: $secret" >> $HOME_FOLDERS_DIR$username"/user_information.txt"
}

function makeConfig(){
	username=$1

	KEY_DIR=$CONFIG_DIR"client-configs/keys/"
	OUTPUT_DIR=$CONFIG_DIR"client-configs/files/"
	BASE_CONFIG=$CONFIG_DIR"client-configs/base.conf"

	cat ${BASE_CONFIG} \
	  <(echo -e '<ca>') \
	  ${KEY_DIR}ca.crt \
	  <(echo -e '</ca>\n<cert>') \
	  ${KEY_DIR}$username.crt \
	  <(echo -e '</cert>\n<key>') \
	  ${KEY_DIR}$username.key \
	  <(echo -e '</key>\n<tls-crypt>') \
	  ${KEY_DIR}ta.key \
	  <(echo -e '</tls-crypt>') \
	  > ${OUTPUT_DIR}$username.ovpn
}

# function to create user .ovpn file
function createOVPNFile(){
	username=$1

	cd /opt/openvpn/client-configs/
	# check that key doesn't already exists
	if ! [ -f $CONFIG_DIR"client-configs/pki/private/$username.key" ]; then
		$($EASYRSA --batch --req-cn=$username gen-req $username nopass 1>/dev/null 2>/dev/null)
		$($EASYRSA --batch sign-req client $username 1>/dev/null 2>/dev/null)

		if ([ -f $CONFIG_DIR"client-configs/pki/private/$username.key" ] && [ -f $CONFIG_DIR"client-configs/pki/issued/$username.crt" ]); then
			cp $CONFIG_DIR"client-configs/pki/private/$username.key" $CONFIG_DIR"client-configs/keys/"
			cp $CONFIG_DIR"client-configs/pki/issued/$username.crt" $CONFIG_DIR"client-configs/keys/"
		else
			echo "Problems while creating user's certificates"
			exit 1
		fi
	fi
	cd ..

	$(makeConfig $username)
	mv $CONFIG_DIR"client-configs/files/"$username".ovpn" $HOME_FOLDERS_DIR$username"/"
}

function createCCDFile(){
	username=$1
	group=$(($2*2))
	final_ip=""

	# write current amount of used subnets IP into a file, both for group a and b
	if [ $group -eq $(($GROUP_A*2)) ]; then
		# read group_a ip counter
		final_ip=$(cat $CONFIG_DIR_OVPN"group_a_counter.txt")
		# imcrement counter in file
		echo $(($final_ip+1)) > $CONFIG_DIR_OVPN"group_a_counter.txt"
	else
		# read group_b ip counter
		final_ip=$(cat $CONFIG_DIR_OVPN"group_b_counter.txt")
		# increment counter in file
		echo $(($final_ip+1)) > $CONFIG_DIR_OVPN"group_b_counter.txt"
	fi

	text="ifconfig-push 10.8.$group.$final_ip 255.255.0.0"
	# add path for the file
	echo $text > $CONFIG_DIR_OVPN$username
}

function sendFilesToUser(){
	username=$1
	subject=$2
	message=$3

	cd $HOME_FOLDERS_DIR
	$(which zip) "$username.zip" "$username/qr.png" "$username/user_information.txt" "$username/$username.ovpn" >/dev/null

	echo "$message" | $(which mail) -s "$subject" -A "$username.zip" $ADMIN_EMAIL
	rm "$username.zip"

	cd $CONFIG_DIR
}

# function to create a user, activated with -c option and the other required
function createUser(){
	username=$1
	group=$2

	created="FALSE"
	if [ $(isUserValid "$username") = "FALSE" ]; then
		$(which useradd) -m -d "$HOME_FOLDERS_DIR$username" -s "/usr/sbin/nologin" "$username"
		echo "username: $username" >> $HOME_FOLDERS_DIR$username"/user_information.txt"

		$(setUserPassword $username)
		$(chage -m 0 -M 99999 -I -1 -E -1 $username)

		$(create2FA $username)

		$(createOVPNFile $username)

		$(createCCDFile $username $group)

		$(sendFilesToUser $username "VPN Details for user: $username" "VPN details after user creation")

		created="TRUE"
	fi

	echo $created
}

function decrementCounter(){
	username=$1

	IFS=" ";
	read -ra array <<< $(cat $CONFIG_DIR_OVPN$username)
	ip=${array[1]}

	IFS="."
	read -ra array <<< $(echo $ip)
	tmp=${array[0]}

	IFS=" "
	read -ra array <<< $(echo $tmp)

	ip=${array[2]}
	group=$(echo "$ip / 2" | bc)

	if [ $group -eq $GROUP_A ]; then
		counter=$(cat $CONFIG_DIR_OVPN"group_a_counter.txt")
		echo $(($counter-1)) > $CONFIG_DIR_OVPN"group_a_counter.txt"
	else
		counter=$(cat $CONFIG_DIR_OVPN"group_b_counter.txt")
                echo $(($counter-1)) > $CONFIG_DIR_OVPN"group_b_counter.txt"
	fi
}

# function to delete a user, activated with -d option and the other required
function deleteUser(){
	username=$1

	deleted="FALSE"
	rm=$(which rm)
	$(which userdel) $username
	$rm -rf "$HOME_FOLDERS_DIR$username"
	$rm $CONFIG_DIR"google-auth/"$username
	$rm $CONFIG_DIR"client-configs/pki/private/"$username".key"
	$rm $CONFIG_DIR"client-configs/keys/"$username".key"
	$rm $CONFIG_DIR"client-configs/keys/"$username".crt"
	$rm $CONFIG_DIR"client-configs/pki/issued/"$username".crt"
	$(decrementCounter $username)
	$rm $CONFIG_DIR_OVPN$username
	deleted="TRUE"

	echo $deleted
}

# print usage if no option is passed
if [[ ${#} -eq 0 ]]; then usage; fi

create="FALSE"
delete="FALSE"
reset="FALSE"
username="NOTSET"
group=0

optstring="hcdru:g:"
while getopts ${optstring} opt; do
  case $opt in
    	h) usage ;;
	c) create="TRUE" ;;
	d) delete="TRUE" ;;
	r) reset="TRUE" ;;
	u)
		if ! [[ $OPTARG =~ ^[A-Za-z0-9_.]+$ ]]; then
			echo "Username is invalid"
			exit 1
		else
			username=$OPTARG
		fi
		;;
	g)
		if [[ $OPTARG =~ ^[0-9]$ ]] && (( $(($OPTARG)) >= 1 )) && (( $(($OPTARG)) <= 2 )); then
			group=$OPTARG
		else
			echo "Group is invalid"
			echo "Available options: "
			echo "- 1 = Users of type 1"
			echo "- 2 = Users of type 2"
			exit 1
		fi
		;;
	?)
      		echo "Invalid option: -${OPTARG}."
      		echo
      		usage
      		;;
	:)
		echo "Option -$OPTARG requires an argument." >&2
       		exit 1
       		;;
	*)
		exit 1 ;;
	esac
done

if ! [ "$username" = "NOTSET" ]; then
	#check if username is present in the linux database
	if ! [ $(isUserValid $username) = "TRUE" ] && ! [ $create = "TRUE" ]; then
		echo "Username not found in the linux database"
		exit 1
	fi

	# create function
	if [ "$create" = "TRUE" ] && ! ([ "$delete" = "TRUE" ] || [ "$reset" = "TRUE" ]); then
		if ! [ $group = 0 ]; then
			echo "--- CREATE USER ---"
			echo "username: $username"
			echo "group: $group"
			echo "home directory: $HOME_FOLDERS_DIR$username"
			echo

			if [ "$(createUser $username $group)" = "TRUE" ]; then
				echo "User successfully created"
			else
				echo "User not created because it is already present in the Linux Database or because there were errors during the process"
				exit 1
			fi
		else
			echo "-g <group> option is required"
			exit 1
		fi
	# delete function
	elif [ "$delete" = "TRUE" ] && ! ([ "$create" = "TRUE" ] || [ "$reset" = "TRUE" ]); then
		echo "--- DELETE USER ---"
		echo "username: $username"
		echo "home directory: $HOME_FOLDERS_DIR$username"
		echo

		if [ "$(deleteUser $username)" = "TRUE" ]; then
			echo "User successfully deleted"
		fi
	# reset password
	elif [ "$reset" = "TRUE" ] && ! ([ "$delete" = "TRUE" ] || [ "$create" = "TRUE" ]); then
		echo "--- RESET USER's PASSWORD ---"
		echo "username: $username"

		echo "username: $username" > $HOME_FOLDERS_DIR$username"/user_information.txt"
		$(setUserPassword $username)

		secret=$(head -n 1 $(echo $CONFIG_DIR"google-auth/"$username))
		echo "2FA secret: $secret" >> $HOME_FOLDERS_DIR$username"/user_information.txt"

		$(sendFilesToUser $username "New VPN Details for user: $username" "VPN details after password reset")
	else
		echo "-c, -d, -r can\'t be used together"
		echo
		usage
	fi
else
	echo "-u <username> option is required"
fi
