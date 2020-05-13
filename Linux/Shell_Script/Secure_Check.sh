ng_check=`locale -a 2>/dev/null | grep "en_US" | egrep -i "(utf8|utf-8)"`
if [ "$lang_check" = "" ]; then
	lang_check="C"
fi

LANG="$lang_check"
LC_ALL="$lang_check"
LANGUAGE="$lang_check"
export LANG
export LC_ALL
export LANGUAGE

##### 포트 명령어 설정
if [ "`command -v netstat 2>/dev/null`" != "" ] || [ "`which netstat 2>/dev/null`" != "" ]; then
	port_cmd="netstat"
else
	port_cmd="ss"
fi

if [ "`command -v systemctl 2>/dev/null`" != "" ] || [ "`which systemctl 2>/dev/null`" != "" ]; then
	systemctl_cmd="systemctl"
fi


##### 수집 파일 지정
RESULT_COLLECT_FILE="Result_Collect_`date +\"%Y%m%d%H%M\"`.txt"
RESULT_VALUE_FILE="Result_Value_`date +\"%Y%m%d%H%M\"`.txt"
##### 시스템 기본 정보 수집
echo "[Start Script]"
echo "====================== Linux Security Check Script Start ======================" >> $RESULT_COLLECT_FILE 2>&1
echo "====================== Linux Security Check Script Start ======================" >> $RESULT_VALUE_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_VALUE_FILE 2>&1

function u01() {
################################################################################################
#
# - 주요 정보 통신 기반 시설 | 계정 관리
# - U-01 root 계정 원격접속 제한
#
################################################################################################

echo "[ U-01 ] : Check"
echo "====================== [U-01 root 계정 원격접속 제한 START]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1

echo "1. SSH" >> $RESULT_COLLECT_FILE 2>&1
echo "1-1. SSH Process Check" >> $RESULT_COLLECT_FILE 2>&1
get_ssh_ps=`ps -ef | grep -v "grep" | grep "sshd"`
if [ "$get_ssh_ps" != "" ]; then
	echo "$get_ssh_ps" >> $RESULT_COLLECT_FILE 2>&1
else
	echo "Not Found Process" >> $RESULT_COLLECT_FILE 2>&1
fi
echo "" >> $RESULT_COLLECT_FILE 2>&1

echo "1-2. SSH Service Check" >> $RESULT_COLLECT_FILE 2>&1
if [ "$systemctl_cmd" != "" ]; then
	get_ssh_service=`$systemctl_cmd list-units --type service | egrep '(ssh|sshd)\.service' | sed -e 's/^ *//g' -e 's/^	*//g' | tr -s " \t"`
	if [ "$get_ssh_service" != "" ]; then
		echo "$get_ssh_service" >> $RESULT_COLLECT_FILE 2>&1
	else
		echo "Not Found Service" >> $RESULT_COLLECT_FILE 2>&1
	fi
else
	echo "Not Found systemctl Command" >> $RESULT_COLLECT_FILE 2>&1
fi
echo "" >> $RESULT_COLLECT_FILE 2>&1

echo "1-3. SSH Port Check" >> $RESULT_COLLECT_FILE 2>&1
if [ "$port_cmd" != "" ]; then
	get_ssh_port=`$port_cmd -na | grep "tcp" | grep "LISTEN" | grep ':22[ \t]'`
	if [ "$get_ssh_port" != "" ]; then
		echo "$get_ssh_port" >> $RESULT_COLLECT_FILE 2>&1
	else
		echo "Not Found Port" >> $RESULT_COLLECT_FILE 2>&1
	fi
else
	echo "Not Found Port Command" >> $RESULT_COLLECT_FILE 2>&1
fi

if [ "$get_ssh_ps" != "" ] || [ "$get_ssh_service" != "" ] || [ "$get_ssh_port" != "" ]; then
	echo "" >> $RESULT_COLLECT_FILE 2>&1
	echo "1-4. SSH Configuration File Check" >> $RESULT_COLLECT_FILE 2>&1
	if [ -f "/etc/ssh/sshd_config" ]; then
		get_ssh_conf=`cat /etc/ssh/sshd_config | egrep -v '^#|^$' | grep "PermitRootLogin"`
		if [ "$get_ssh_conf" != "" ]; then
			echo "/etc/ssh/sshd_config : $get_ssh_conf" >> $RESULT_COLLECT_FILE 2>&1
			get_conf_check=`echo "$get_ssh_conf" | awk '{ print $2 }'`
			if [ "$get_conf_check" = "no" ]; then
				ssh_flag=1
			else
				ssh_flag=0
			fi
		else
			ssh_flag=1
			echo "/etc/ssh/sshd_config : Not Found PermitRootLogin Configuration" >> $RESULT_COLLECT_FILE 2>&1
		fi
	else
		ssh_flag=2
		echo "Not Found SSH Configuration File" >> $RESULT_COLLECT_FILE 2>&1
	fi
	echo "" >> $RESULT_COLLECT_FILE 2>&1
else
	ssh_flag=1
fi

echo "2. Telnet" >> $RESULT_COLLECT_FILE 2>&1
echo "2-1. Telnet Process Check" >> $RESULT_COLLECT_FILE 2>&1
get_telnet_ps=`ps -ef | grep -v "grep" | grep "telnet"`
if [ "$get_telnet_ps" != "" ]; then
	echo "$get_telnet_ps" >> $RESULT_COLLECT_FILE 2>&1
else
	echo "Not Found Process" >> $RESULT_COLLECT_FILE 2>&1
fi
echo "" >> $RESULT_COLLECT_FILE 2>&1

echo "2-2. Telnet Service Check" >> $RESULT_COLLECT_FILE 2>&1
if [ "$systemctl_cmd" != "" ]; then
	get_telnet_service=`$systemctl_cmd list-units --type service | egrep '(telnet|telnetd)\.service' | sed -e 's/^ *//g' -e 's/^	*//g' | tr -s " \t"`
	if [ "$get_telnet_service" != "" ]; then
		echo "$get_telnet_service" >> $RESULT_COLLECT_FILE 2>&1
	else
		echo "Not Found Service" >> $RESULT_COLLECT_FILE 2>&1
	fi
else
	echo "Not Found systemctl Command" >> $RESULT_COLLECT_FILE 2>&1
fi
echo "" >> $RESULT_COLLECT_FILE 2>&1

echo "2-3. Telnet Port Check" >> $RESULT_COLLECT_FILE 2>&1
if [ "$port_cmd" != "" ]; then
	get_telnet_port=`$port_cmd -na | grep "tcp" | grep "LISTEN" | grep ':23[ \t]'`
	if [ "$get_telnet_port" != "" ]; then
		echo "$get_telnet_port" >> $RESULT_COLLECT_FILE 2>&1
	else
		echo "Not Found Port" >> $RESULT_COLLECT_FILE 2>&1
	fi
else
	echo "Not Found Port Command" >> $RESULT_COLLECT_FILE 2>&1
fi

if [ "$get_telnet_ps" != "" ] || [ "$get_telnet_service" != "" ] || [ "$get_telnet_port" != "" ]; then
	echo "" >> $RESULT_COLLECT_FILE 2>&1
	echo "2.4 Telnet Configuration Check" >> $RESULT_COLLECT_FILE 2>&1
	if [ -f "/etc/pam.d/remote" ]; then
		pam_file="/etc/pam.d/remote"
	elif [ -f "/etc/pam.d/login" ]; then
		pam_file="/etc/pam.d/login"
	fi

	if [ "$pam_file" != "" ]; then
		echo "- $pam_file" >> $RESULT_COLLECT_FILE 2>&1
		get_conf=`cat $pam_file | egrep -v '^#|^$' | grep "pam_securetty.so"`
		if [ "$get_conf" != "" ]; then
			echo "$get_conf" >> $RESULT_COLLECT_FILE 2>&1
			if [ -f "/etc/securetty" ]; then
				echo "- /etc/securetty" >> $RESULT_COLLECT_FILE 2>&1
				get_pts=`cat /etc/securetty | egrep -v '^#|^$' | grep "^[ \t]*pts"` >> $RESULT_COLLECT_FILE 2>&1
				if [ "$get_pts" != "" ]; then
					telnet_flag=0
				else
					telnet_flag=1
				fi
			else
				telnet_flag=0
				echo "Not Found Telnet tty Configuration File" >> $RESULT_COLLECT_FILE 2>&1
			fi
		else
			telnet_flag=0
			echo "$pam_file : Not Found pam_securetty.so Configuration" >> $RESULT_COLLECT_FILE 2>&1
		fi
	else
		telnet_flag=2
		echo "Not Found Telnet Pam Configuration File" >> $RESULT_COLLECT_FILE 2>&1
	fi
else
	telnet_flag=1
fi

# 양호 : 1, 취약 : 0, 검토 : 2
if [ $ssh_flag -eq 1 ] && [ $telnet_flag -eq 1 ]; then
	echo "[ U-01 ] : 양호" >> $RESULT_VALUE_FILE 2>&1
elif [ $ssh_flag -eq 0 ] || [ $telnet_flag -eq 0 ]; then
	echo "[ U-01 ] : 취약" >> $RESULT_VALUE_FILE 2>&1
elif [ $ssh_flag -eq 2 ] || [ $telnet_flag -eq 2 ]; then
	echo "[ U-01 ] : 검토" >> $RESULT_VALUE_FILE 2>&1
fi

echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "====================== [U-01 root 계정 원격접속 제한 END]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
}

function u02() {
################################################################################################
#
# - 주요 정보 통신 기반 시설 | 계정 관리
# - U-02 패스워드 복잡성 설정 
#
################################################################################################
echo "[ U-02 ] : Check"
echo "====================== [U-02 패스워드 복잡성 설정 START]" >> $RESULT_COLLECT_FILE 2>&1
echo ""	>> $RESULT_COLLECT_FILE 2>&1

if [ -f /etc/security/pwquality.conf ]; then

	echo -e "- /etc/security/pwquality.conf\n" >> $RESULT_COLLECT_FILE 2>&1

	lcredit_conf=`cat /etc/security/pwquality.conf | egrep -v '^#|^$' | sed 's/ //g' | grep lcredit`
	lcredit_flag=`cat /etc/security/pwquality.conf | egrep -v '^#|^$' | grep lcredit | awk '/[-1~]/' | awk '{ print substr($3,1,1) }'`
	pwd_count=0

	if [ "$lcredit_conf" != "" ]; then
		if [ "$lcredit_flag" = "-" ]; then
			echo "$lcredit_conf" >> $RESULT_COLLECT_FILE 2>&1
			pwd_count=`expr $pwd_count + 1`
		else
			echo "$lcredit_conf" >> $RESULT_COLLECT_FILE 2>&1
		fi
	else
		echo "Not Found lcredit Configuration" >> $RESULT_COLLECT_FILE 2>&1
	fi

	ucredit_conf=`cat /etc/security/pwquality.conf | egrep -v '^#|^$' | sed 's/ //g' | grep ucredit`
	ucredit_flag=`cat /etc/security/pwquality.conf | egrep -v '^#|^$' | grep ucredit | awk '/[-1~]/' | awk '{ print substr($3,1,1) }'`

	if [ "$ucredit_conf" != "" ]; then
		if [ "$ucredit_flag" = "-" ]; then
			echo "$ucredit_conf" >> $RESULT_COLLECT_FILE 2>&1
			pwd_count=`expr $pwd_count + 1`
		else
			echo "$ucredit_conf" >> $RESULT_COLLECT_FILE 2>&1
		fi
	else
		echo "Not Found ucredit Configuration" >> $RESULT_COLLECT_FILE 2>&1
	fi

	dcredit_conf=`cat /etc/security/pwquality.conf | egrep -v '^#|^$' | sed 's/ //g' | grep dcredit`
	dcredit_flag=`cat /etc/security/pwquality.conf | egrep -v '^#|^$' | grep dcredit | awk '/[-1~]/' | awk '{ print substr($3,1,1) }'`

	if [ "$dcredit_conf" != "" ]; then
		if [ "$dcredit_flag" = "-" ]; then
			echo "$dcredit_conf" >> $RESULT_COLLECT_FILE 2>&1
			pwd_count=`expr $pwd_count + 1`
		else
			echo "$dcredit_conf" >> $RESULT_COLLECT_FILE 2>&1
		fi
	else
		echo "Not Found dcredit Configuration" >> $RESULT_COLLECT_FILE 2>&1
	fi

	ocredit_conf=`cat /etc/security/pwquality.conf | egrep -v '^#|^$' | sed 's/ //g' | grep ocredit`
	ocredit_flag=`cat /etc/security/pwquality.conf | egrep -v '^#|^$' | grep odcedit | awk '/[-1~]/' | awk '{ print substr($3,1,1) }'`

	if [ "$ocredit_conf" != "" ]; then
		if [ "$ocredit_flag" = "-" ]; then
			echo "$ocredit_conf" >> $RESULT_COLLECT_FILE 2>&1
			pwd_count=`expr $pwd_count + 1`
		else
			echo "$ocredit_conf" >> $RESULT_COLLECT_FILE 2>&1
		fi
	else
		echo "Not Found ocredit Configuration" >> $RESULT_COLLECT_FILE 2>&1
	fi

	pwd_len_conf=`cat /etc/security/pwquality.conf | egrep -v '^#|^$' | sed 's/ //g' | grep minlen`
	pwd_len_flag=`cat /etc/security/pwquality.conf | egrep -v '^#|^$' | grep minlen | grep -o '[0-9]*'`

	if [ "$pwd_len_conf" != "" ]; then
		echo `cat /etc/security/pwquality.conf | grep minlen` >> $RESULT_COLLECT_FILE 2>&1
		if [ $pwd_count -eq 2 ] && [ $pwd_len_flag -ge 10 ]; then 
			echo "[ U-02 ] : 양호" >> $RESULT_VALUE_FILE 2>&1
		elif [ $pwd_count -ge 3 ] && [ $pwd_len_flag -ge 8 ]; then
			echo "[ U-02 ] : 양호" >> $RESULT_VALUE_FILE 2>&1
		else
			echo "[ U-02 ] : 취약" >> $RESULT_VALUE_FILE 2>&1
		fi
	else
		echo "[ U-02 ] : 취약" >> $RESULT_VALUE_FILE 2>&1
		echo "Not Found Password Length Configuration" >> $RESULT_COLLECT_FILE 2>&1
	fi

else
	echo "Not Found /etc/security/pwquality.conf" >> $RESULT_COLLECT_FILE 2>&1
	echo "[ U-02 ] : 취약" >> $RESULT_VALUE_FILE 2>&1
fi

echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "====================== [U-02 패스워드 복잡성 설정 END]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
}

function u03() {
################################################################################################
#
# - 주요 정보 통신 기반 시설 | 계정 관리
# - U-03 계정 잠금 임계값 설정
#
################################################################################################

echo "[ U-03 ] : Check"
echo "====================== [U-03 계정 잠금 임계값 설정 START]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1

retries_path="/etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/common-auth /etc/pam.d/common-account"
get_deny_count=0
for file in $retries_path; do
	echo "- $file" >> $RESULT_COLLECT_FILE 2>&1
	if [ -f "$file" ]; then
		get_deny=`cat "$file" | grep -v '^#'  | grep 'pam_tally' | egrep 'deny|lock_time'`
		if [ "$get_deny" != "" ]; then
			echo "$get_deny" >> $RESULT_COLLECT_FILE 2>&1
			get_deny_count=`expr $get_deny_count + 1`
		else
			echo "Not Found Retries & Lock Time" >> $RESULT_COLLECT_FILE 2>&1
		fi
	else
		echo "Not Found Configuration File" >> $RESULT_COLLECT_FILE 2>&1
	fi
	echo "" >> $RESULT_COLLECT_FILE 2>&1
done

if [ "$get_deny_count" -gt 0 ]; then
	echo "[ U-03 ] : 양호" >> $RESULT_VALUE_FILE 2>&1
else
	echo "[ U-03 ] : 취약" >> $RESULT_VALUE_FILE 2>&1
fi

echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "====================== [U-03 계정 잠금 임계값 설정 END]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
}

function u04() {
################################################################################################
#
# - 주요 정보 통신 기반 시설 | 계정 관리
# - U-04 패스워드 파일 보호
#
################################################################################################

echo "[ U-04 ] : Check"
echo "====================== [U-04 패스워드 파일 보호 START]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1

if [ -f "/etc/passwd" ]; then
	passwd_conf=(`cat /etc/passwd`)
	passwd_count=0

	echo "1. /etc/passwd File Check" >> $RESULT_COLLECT_FILE 2>&1

	for i in ${passwd_conf[@]}
	do
		if [ "`echo $i | awk -F: '{print $2}' | egrep -v 'x|^/'`" != "" ]; then
			passwd_count=`expr $passwd_count + 1`
			echo "$i" >> $RESULT_COLLECT_FILE 2>&1
		fi
	done
else
	echo -e "Not Found /etc/passwd File\n" >> $RESULT_COLLECT_FILE 2>&1
fi

echo "" >> $RESULT_COLLECT_FILE 2>&1

if [ -f "/etc/shadow" ]; then
	shadow_conf=(`cat /etc/shadow`)
	shadow_count=0

	echo "2. /etc/shadow File Check" >> $RESULT_COLLECT_FILE 2>&1

	for a in ${shadow_conf[@]}
	do
		if [ "`echo $a | awk -F: '{print $2}' | egrep -v '^!|^\*|^\\$'`" != "" ]; then
			shadow_count=`expr $shadow_count + 1`
			echo "$a" >> $RESULT_COLLECT_FILE 2>&1
		fi
	done
else
	echo -e "Not Found /etc/shadow File\n" >> $RESULT_COLLECT_FILE 2>&1
fi

if [ -f "/etc/shadow" ] && [ $passwd_count -eq 0 ] && [ $shadow_count -eq 0 ]; then
	echo "[ U-04 ] : 양호" >> $RESULT_VALUE_FILE 2>&1
else
	echo "[ U-04 ] : 취약" >> $RESULT_VALUE_FILE 2>&1
fi
echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "====================== [U-04 패스워드 파일 보호 END]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
}

function u05() {
################################################################################################
#
# - 주요 정보 통신 기반 시설 | 파일 및 디렉터리 관리
# - U-05 root 홈, 패스 디렉터리 권한 및 패스 설정
#
################################################################################################
echo "[ U-05 ] : Check"
echo "====================== [U-05 root 홈, 패스 디렉터리 권한 및 패스 설정 START]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1

path=("`echo $PATH | sed 's/\\\*/ /g' | awk -F" " '{ for(i=1;i<NF;i++) if($i ~ /\./) printf "%s ", $i}'`")

echo "$PATH" >> $RESULT_COLLECT_FILE 2>&1
if [ "$path" != "" ]; then
        echo "[ U-05 ] : 취약" >> $RESULT_VALUE_FILE 2>&1
else
        echo "[ U-05 ] : 양호" >> $RESULT_VALUE_FILE 2>&1
fi

echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "====================== [U-05 root 홈, 패스 디렉터리 권한 및 패스 설정 END]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
}

function u06() {
################################################################################################
#
# - 주요 정보 통신 기반 시설 | 파일 및 디렉터리 관리
# - U-06 파일 및 디렉터리 소유자 설정
#
################################################################################################
echo "[ U-06 ] : Check"
echo "====================== [U-06 파일 및 디렉터리 소유자 설정 START]" >> $RESULT_COLLECT_FILE 2>&1
echo >> $RESULT_COLLECT_FILE 2>&1

nouser_list=("`find / -nouser -print 2>/dev/null`")
nogroup_list=("`find / -nogroup -print 2>/dev/null`")

if [ "${nouser_list[@]}" != "" ]; then
	echo -e "NoUser File and Directory List\n" >> $RESULT_COLLECT_FILE 2>&1
        for i in ${nouser_list[@]}
        do
                echo $i >> $RESULT_COLLECT_FILE 2>&1
        done
else
	echo -e "Not Found NoUser File and Directory" >> $RESULT_COLLECT_FILE 2>&1 
fi

if [ "${nogroup_list[@]}" != "" ]; then
	echo >> $RESULT_COLLECT_FILE 2>&1
	echo -e "No Group File and Directory List\n" >> $RESULT_COLLECT_FILE 2>&1
        for k in ${nogroup_list[@]}
        do
                echo $k >> $RESULT_COLLECT_FILE 2>&1
        done
else
	echo -e "Not Found NoGroup File and Directory" >> $RESULT_COLLECT_FILE 2>&1 
fi

if [ "${nouser_list[@]}" != "" ] && [ "${nogroup_list[@]}" != "" ]; then
        echo "[ U-06 ] : 취약" >> $RESULT_VALUE_FILE 2>&1
else
        echo "[ U-06 ] : 양호" >> $RESULT_VALUE_FILE 2>&1
fi

echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "====================== [U-06 파일 및 디렉터리 소유자 설정 END]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
}


function u07() {
################################################################################################
#
# - 주요 정보 통신 기반 시설 | 파일 및 디렉터리 관리
# - U-07 /etc/passwd 파일 소유자 및 권한 설정
#
################################################################################################

echo "[ U-07 ] : Check"
echo "====================== [U-07 /etc/passwd 파일 소유자 및 권한 설정 START]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1

if [ -f "/etc/passwd" ]; then
	ls -l /etc/passwd >> $RESULT_COLLECT_FILE 2>&1
	permission_val=`stat -c '%a' /etc/passwd`
	owner_val=`stat -c '%U' /etc/passwd`

	owner_perm_val=`echo "$permission_val" | awk '{ print substr($0, 1, 1) }'`
	group_perm_val=`echo "$permission_val" | awk '{ print substr($0, 2, 1) }'`
	other_perm_val=`echo "$permission_val" | awk '{ print substr($0, 3, 1) }'`

	if [ "$owner_perm_val" -le 6 ] && [ "$group_perm_val" -le 4 ] && [ "$other_perm_val" -le 4 ] && [ "$owner_val" = "root" ]; then
		echo "[ U-07 ] : 양호" >> $RESULT_VALUE_FILE 2>&1
	else
		echo "[ U-07 ] : 취약" >> $RESULT_VALUE_FILE 2>&1
	fi
else
	echo "Not Found /etc/passwd File" >> $RESULT_COLLECT_FILE 2>&1
	echo "[ U-07 ] : 검토" >> $RESULT_VALUE_FILE 2>&1
fi

echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "====================== [U-07 /etc/passwd 파일 소유자 및 권한 설정 END]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
}

function u08() {
################################################################################################
#
# - 주요 정보 통신 기반 시설 | 파일 및 디렉터리 관리
# - U-08 /etc/shadow 파일 소유자 및 권한 설정
#
################################################################################################

echo "[ U-08 ] : Check"
echo "====================== [U-08 /etc/shadow 파일 소유자 및 권한 설정 START]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1

if [ -f "/etc/shadow" ]; then
	ls -l /etc/shadow >> $RESULT_COLLECT_FILE 2>&1
	permission_val=`stat -c '%a' /etc/shadow`
	owner_val=`stat -c '%U' /etc/shadow`

	if [ "$permission_val" -eq 0 ]; then
		permission_val="000"
	fi

	owner_perm_val=`echo "$permission_val" | awk '{ print substr($0, 1, 1) }'`
	group_perm_val=`echo "$permission_val" | awk '{ print substr($0, 2, 1) }'`
	other_perm_val=`echo "$permission_val" | awk '{ print substr($0, 3, 1) }'`

	if [ "$owner_perm_val" -le 6 ] && [ "$group_perm_val" -eq 0 ] && [ "$other_perm_val" -eq 0 ] && [ "$owner_val" = "root" ]; then
		echo "[ U-08 ] : 양호" >> $RESULT_VALUE_FILE 2>&1
	else
		echo "[ U-08 ] : 취약" >> $RESULT_VALUE_FILE 2>&1
	fi
else
	echo "Not Found /etc/shadow File" >> $RESULT_COLLECT_FILE 2>&1
	echo "[ U-08 ] : 검토" >> $RESULT_VALUE_FILE 2>&1
fi

echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "====================== [U-08 /etc/shadow 파일 소유자 및 권한 설정 END]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
}

function u09() {
################################################################################################
#
# - 주요 정보 통신 기반 시설 | 파일 및 디렉터리 관리
# - U-09 /etc/hosts 파일 소유자 및 권한 설정
#
################################################################################################

echo "[ U-09 ] : Check"
echo "====================== [U-09 /etc/hosts 파일 소유자 및 권한 설정 START]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1

if [ -f "/etc/hosts" ]; then
        ls -l /etc/hosts >> $RESULT_COLLECT_FILE 2>&1
        permission_val=`stat -c '%a' /etc/hosts`
        owner_val=`stat -c '%U' /etc/hosts`

        if [ "$permission_val" -eq 0 ]; then
                permission_val="000"
        fi

        owner_perm_val=`echo "$permission_val" | awk '{ print substr($0, 1, 1) }'`
        group_perm_val=`echo "$permission_val" | awk '{ print substr($0, 2, 1) }'`
        other_perm_val=`echo "$permission_val" | awk '{ print substr($0, 3, 1) }'`

        if [ "$owner_perm_val" -le 6 ] && [ "$group_perm_val" -eq 0 ] && [ "$other_perm_val" -eq 0 ] && [ "$owner_val" = "root" ]; then
                echo "[ U-09 ] : 양호" >> $RESULT_VALUE_FILE 2>&1
        else
                echo "[ U-09 ] : 취약" >> $RESULT_VALUE_FILE 2>&1
        fi
else
        echo "Not Found /etc/hosts File" >> $RESULT_COLLECT_FILE 2>&1
        echo "[ U-09 ] : 검토" >> $RESULT_VALUE_FILE 2>&1
fi

echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "====================== [U-09 /etc/hosts 파일 소유자 및 권한 설정 END]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
}

function u10() {
################################################################################################
#
# - 주요 정보 통신 기반 시설 | 파일 및 디렉터리 관리
# - U-10 /etc/xinetd 파일 소유자 및 권한 설정
#
################################################################################################

echo "[ U-10 ] : Check"
echo "====================== [U-10 /etc/xinetd 파일 소유자 및 권한 설정 START]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1

xinetd_service=`rpm -qa | grep xinetd`

if [ "$xinetd_service" != "" ]; then

	xinetd_count=0
	conffile=`ps -ef | grep xinet | grep -v "grep" | awk -F-f '{print $2}' | sed 's/^ *//g'`	

	if [ "$conffile" = "" ]; then
		conffile=/etc/xinetd.conf
	fi

	syslogfile=`ps -ef | grep xinet | grep -v "grep" | awk -F-syslog '{print $2}' | sed 's/^ *//g'`

	if [ "$syslogfile" = "" ]; then
		syslogfile=/etc/sysconfig/xinetd
	fi

	include_option="`cat $conffile | egrep -v '[#]|^$' | grep -i includedir | awk '{print $2}'`"
	include_file="`find $include_option -type f -exec ls {} \;`"
		

        FileList=("$syslogfile $conffile $include_file")
        for i in $FileList
        do
                ls -l $i >> $RESULT_COLLECT_FILE 2>&1

		permission_val=`stat -c '%a' "$i"`
        	owner_val=`stat -c '%U' "$i"`

        	if [ "$permission_val" -eq 0 ]; then
                	permission_val="000"
        	fi

        	owner_perm_val=`echo "$permission_val" | awk '{ print substr($0, 1, 1) }'`
        	group_perm_val=`echo "$permission_val" | awk '{ print substr($0, 2, 1) }'`
        	other_perm_val=`echo "$permission_val" | awk '{ print substr($0, 3, 1) }'`

        	if [ "$owner_perm_val" -le 6 ] && [ "$group_perm_val" -eq 0 ] && [ "$other_perm_val" -eq 0 ] && [ "$owner_val" = "root" ]; then
                	xinet_count=`expr $xinet_count + 0`
        	else
                	xinet_count=`expr $xinet_count + 1`
        	fi
        done
	if [ "$xinet_count" -eq 0 ]; then
		echo "[ U-10 ] : 양호" >> $RESULT_VALUE_FILE 2>&1
	else
		echo "[ U-10 ] : 취약" >> $RESULT_VALUE_FILE 2>&1
	fi



else
        echo "Not Found Xinetd Process and Configuration Files" >> $RESULT_COLLECT_FILE 2>&1
	echo "[ U-10 ] : 검토(or 미설치)" >> $RESULT_VALUE_FILE 2>&1
fi
echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "====================== [U-10 xinetd 파일 소유자 및 권한 설정 END]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
}

function u11() {
################################################################################################
#
# - 주요 정보 통신 기반 시설 | 파일 및 디렉터리 관리
# - U-11 /etc/syslog.conf 파일 소유자 및 권한 설정
#
################################################################################################

echo "[ U-11 ] : Check"
echo "====================== [U-11 /etc/syslog.conf 파일 소유자 및 권한 설정 START]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1

if [ -f "/etc/rsyslog.conf" ]; then
        ls -l /etc/rsyslog.conf >> $RESULT_COLLECT_FILE 2>&1
        permission_val=`stat -c '%a' /etc/rsyslog.conf`
        owner_val=`stat -c '%U' /etc/rsyslog.conf`

        if [ "$permission_val" -eq 0 ]; then
                permission_val="000"
        fi

        owner_perm_val=`echo "$permission_val" | awk '{ print substr($0, 1, 1) }'`
        group_perm_val=`echo "$permission_val" | awk '{ print substr($0, 2, 1) }'`
        other_perm_val=`echo "$permission_val" | awk '{ print substr($0, 3, 1) }'`

        if [ "$owner_perm_val" -le 6 ] && [ "$group_perm_val" -le 4 ] && [ "$other_perm_val" -le 4 ] && [ "$owner_val" = "root" ]; then
                echo "[ U-11 ] : 양호" >> $RESULT_VALUE_FILE 2>&1
        else
                echo "[ U-11 ] : 취약" >> $RESULT_VALUE_FILE 2>&1
        fi
else
        echo "Not Found /etc/rsyslog.conf File" >> $RESULT_COLLECT_FILE 2>&1
        echo "[ U-11 ] : 검토(or 미설치)" >> $RESULT_VALUE_FILE 2>&1
fi

echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "====================== [U-11 /etc/syslog.conf 파일 소유자 및 권한 설정 END]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
}


function u12() {
################################################################################################
#
# - 주요 정보 통신 기반 시설 | 파일 및 디렉터리 관리
# - U-12 /etc/services 파일 소유자 및 권한 설정
#
################################################################################################

echo "[ U-12 ] : Check"
echo "====================== [U-12 /etc/services 파일 소유자 및 권한 설정 START]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1

if [ -f "/etc/services" ]; then
        ls -l /etc/services >> $RESULT_COLLECT_FILE 2>&1
        permission_val=`stat -c '%a' /etc/services`
        owner_val=`stat -c '%U' /etc/services`

        if [ "$permission_val" -eq 0 ]; then
                permission_val="000"
        fi

        owner_perm_val=`echo "$permission_val" | awk '{ print substr($0, 1, 1) }'`
        group_perm_val=`echo "$permission_val" | awk '{ print substr($0, 2, 1) }'`
        other_perm_val=`echo "$permission_val" | awk '{ print substr($0, 3, 1) }'`

        if [ "$owner_perm_val" -le 6 ] && [ "$group_perm_val" -le 4 ] && [ "$other_perm_val" -le 4 ] && [ "$owner_val" = "root" ]; then
                echo "[ U-12 ] : 양호" >> $RESULT_VALUE_FILE 2>&1
        else
                echo "[ U-12 ] : 취약" >> $RESULT_VALUE_FILE 2>&1
        fi
else
        echo "Not Found /etc/services File" >> $RESULT_COLLECT_FILE 2>&1
        echo "[ U-12 ] : 검토" >> $RESULT_VALUE_FILE 2>&1
fi

echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "====================== [U-12 /etc/services 파일 소유자 및 권한 설정 END]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
}

function u13() {
################################################################################################
#
# - 주요 정보 통신 기반 시설 | 파일 및 디렉터리 관리
# - U-13 SUID,SGID,Sticky Bit 설정 파일 점검
#
################################################################################################
echo "[ U-13 ] : Check"
echo "====================== [U-13 SUID,SGID,Sticky Bit 설정 파일 점검 START]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1

Sensitive_Files=("/sbin/dump /sbin/restore /usr/bin/newgrp /sbin/unix_chkpwd /usr/bin/lpq-lpd /usr/bin/lpr /usr/sbin/lpc /usr/bin/lpr-lpd /usr/sbin/lpc-lpd /usr/bin/lpq /usr/bin/lprm-lpd /usr/bin/lprm /usr/bin/at")
SID_find="`find / \( -perm -4000 -o -perm -2000 -o -perm -1000 \) -type f -exec ls {} \; 2>/dev/null`"


if [ "$SID_find" != "" ]; then
        Check_count=0

        echo "1. Special Permission File List" >> $RESULT_COLLECT_FILE 2>&1
        echo "" >> $RESULT_COLLECT_FILE 2>&1
        for Find_List in $SID_find
        do
                echo "`ls -l $Find_List`" >> $RESULT_COLLECT_FILE 2>&1
        done

        echo "" >> $RESULT_COLLECT_FILE 2>&1
        echo "2. Dangerous and Wrong Permission Configuration on the Sensitive Files" >> $RESULT_COLLECT_FILE 2>&1
        echo "" >> $RESULT_COLLECT_FILE 2>&1

        for Check_List in $SID_find
        do
                for Dangerous_List in $Sensitive_Files
                do
                        if [ "$Check_List" == "$Dangerous_List" ]; then
                                echo "$Dangerous_List" >> $RESULT_COLLECT_FILE 2>&1
                                Check_count=`expr $Check_count + 1`
                        fi
                done
        done

        if [ $Check_count -gt 0 ]; then
                echo "[ U-13 ] : 취약" >> $RESULT_VALUE_FILE 2>&1
        else
                echo "Not Found Dangerous and Wrong Permission Configuration on the Sensitive Files" >> $RESULT_COLLECT_FILE 2>&1
                echo "[ U-13 ] : 양호" >> $RESULT_VALUE_FILE 2>&1
        fi
fi
echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "====================== [U-13 SUID,SGID,Sticky Bit 설정 파일 점검 END]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
}

function u14() {
################################################################################################
#
# - 주요 정보 통신 기반 시설 | 파일 및 디렉터리 관리
# - U-14 사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정
#
################################################################################################

echo "[ U-14 ] : Check"
echo "====================== [U-14 사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정 START]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1

if [ -f /etc/passwd ]; then
        userlist=`cat /etc/passwd | awk -F":" '{ if($3 >= 1000)  { printf "%s|%s\n", $1, $6 } }' | grep -v 'nobody'`
	check_count=0
        for user in $userlist
        do
                name=`echo $user | awk -F"|" '{ print $1 }'`
                homedir=`echo $user | awk -F"|" '{ print $2 }'`
                echo " - $name Home Directory" >> $RESULT_COLLECT_FILE 2>&1

                filelist=`find "$homedir" -name \.bash\* -type f -exec ls {} \;`
                for file in $filelist
                do
                        echo "`ls -l $file`" >> $RESULT_COLLECT_FILE 2>&1
                        permission_val=`stat -c '%a' $file`
                        owner_val=`stat -c '%U' $file`
                        group_val=`stat -c '%G' $file`
                        if [ "$permission_val" = "0" ]; then
                            permission_val="000"
                        fi
                owner_perm_val=`echo $permission_val | awk '{ print substr($0, 1, 1) }'`
                group_perm_val=`echo $permission_val | awk '{ print substr($0, 2, 1) }'`
                other_perm_val=`echo $permission_val | awk '{ print substr($0, 3, 1) }'`

                if [ "$owner_perm_val" -le 6 ] && [ "$group_perm_val" -le 6 ] && [ "$other_perm_val" -le 4 ] && [ "`echo $owner_val | egrep "root|$name"`" != "" ] && [ "`echo $group_val | egrep "root|$name"`" != "" ]; then
			check_count=`expr $check_count + 0`
                else
			check_count=`expr $check_count + 1`
                fi
                done
        echo "" >> $RESULT_COLLECT_FILE 2>&1
        done
	
	if [ $check_count -gt 0 ]; then
		echo "[ U-14 ] : 취약" >> $RESULT_VALUE_FILE 2>&1
	else
		echo "[ U-14 ] : 양호" >> $RESULT_VALUE_FILE 2>&1
	fi
else
        echo "Not Found /etc/passwd File" >> $RESULT_COLLECT_FILE 2>&1
fi


echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "====================== [U-14 사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정 END]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
}

function u15() {
################################################################################################
#
# - 주요 정보 통신 기반 시설 | 파일 및 디렉터리 관리
# - U-15 World Writable 파일 점검
#
################################################################################################
echo "[ U-15 ] : Check"
echo "====================== [U-15 World Writable 파일 점검 START]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1

file_list="`find / ! \( -path '/root/.chace*' -o -path '/proc*' -o -path '/sys/fs*' -o -path '/usr/local*' -prune \) -perm -2 -type f -exec ls -al {} \; 2>/dev/null`"

if [ "$file_list" != "" ]; then
        echo "$file_list" >> $RESULT_COLLECT_FILE 2>&1
        echo "[ U-15 ] : 취약" >> $RESULT_VALUE_FILE 2>&1
else
        echo "Not Found World Writable Files" >> $RESULT_COLLECT_FILE 2>&1
        echo "[ U-15 ] : 양호" >> $RESULT_VALUE_FILE 2>&1
fi
echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "====================== [U-15 World Writable 파일 점검 END]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
}

function u16() {
################################################################################################
#
# - 주요 정보 통신 기반 시설 | 파일 및 디렉터리 관리
# - U-16 /dev에 존재하지 않는 device 파일 점검
#
################################################################################################
echo "[ U-16 ] : Check"
echo "====================== [U-16 /dev에 존재하지 않는 device 파일 점검 START]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1

mydevice=`blkid | awk -F: '{print "-o -path "$1}'`
dev_list="`find /dev ! \( -path /dev/null $mydevice \) -type f -exec ls -la {} \;`"

if [ "$dev_list" != "" ]; then
        echo "$dev_list" >> $RESULT_COLLECT_FILE 2>&1
        echo "[ U-16 ] : 취약" >> $RESULT_VALUE_FILE 2>&1
else
        echo "Not Found Unuse Device File" >> $RESULT_COLLECT_FILE 2>&1
        echo "[ U-16 ] : 양호" >> $RESULT_VALUE_FILE 2>&1
fi
echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "====================== [U-16 /dev에 존재하지 않는 device 파일 점검 END]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
}

function u17() {
################################################################################################
#
# - 주요 정보 통신 기반 시설 | 파일 및 디렉터리 관리
# - U-17 $HOME./rhosts, hosts.equiv 사용 금지
#
################################################################################################
echo "[ U-17 ] : Check"
echo "====================== [U-17 $HOME./rhosts, hosts.equiv 사용 금지 START]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1

echo "[ U-17 ] : 검토(or 미설치)" >> $RESULT_VALUE_FILE 2>&1
echo "Unused Clause" >> $RESULT_COLLECT_FILE 2>&1

echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "====================== [U-17 $HOME./rhosts, hosts.equiv 사용 금지 END]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
}

function u18() {
################################################################################################
#
# - 주요 정보 통신 기반 시설 | 파일 및 디렉터리 관리
# - U-18 접속 IP 및 포트 제한
#
################################################################################################

echo "[ U-18 ] : Check"
echo "====================== [U-18 접속 IP 및 포트 제한 START]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1


hosts_count=0
echo "1. /etc/hosts.deny" >> $RESULT_COLLECT_FILE 2>&1

if [ -f /etc/hosts.deny ]; then
        hosts_deny=`cat /etc/hosts.deny | egrep -v '^#|^$' | awk -F: '{print $1}' | grep -i all`
        hosts_deny_ALL=`cat /etc/hosts.deny | egrep -v '^#|^$' | awk -F:  '{print $2}' | grep -i all`

        if [ "$hosts_deny" != "" ]; then
                if [ "$hosts_deny_ALL" != "" ]; then
                        echo "`cat /etc/hosts.deny | egrep -v '^#|^$'`" >> $RESULT_COLLECT_FILE 2>&1

                else
                        echo "`cat /etc/hosts.deny | egrep -v '^#|^$'`" >> $RESULT_COLLECT_FILE 2>&1
                        hosts_count=`expr $hosts_count + 1`
                fi
        else
                echo "Not Found Everyone Deny Configuration"    >> $RESULT_COLLECT_FILE 2>&1
                hosts_count=`expr $hosts_count + 1`

        fi
else
        echo "Not Found /etc/hosts.deny File" >> $RESULT_COLLECT_FILE 2>&1
        hosts_count=`expr $hosts_count + 1`
fi

echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "2. /etc/hosts.allow " >> $RESULT_COLLECT_FILE 2>&1

if [ -f /etc/hosts.allow ]; then
        hosts_allow=`cat /etc/hosts.allow | egrep -v '^#|^$' | awk -F: '{print $1}'`
        hosts_allow_ALL=`cat /etc/hosts.allow | egrep -v '^#|^$' | awk -F: '{print $2}' | grep -i all`
        if [ "$hosts_allow" != "" ]; then
                if [ "$hosts_allow_ALL" != "" ]; then
                        echo "`cat /etc/hosts.allow | egrep -v '^#|^$'`"  >> $RESULT_COLLECT_FILE 2>&1
                        hosts_count=`expr $hosts_count + 1`
                else
                        echo "`cat /etc/hosts.allow | egrep -v '^#|^$'`"  >> $RESULT_COLLECT_FILE 2>&1
                fi
        else
                echo "Not Found Everyone Allow Configuration"    >> $RESULT_COLLECT_FILE 2>&1
                hosts_count=`expr $hosts_count + 1`
        fi
else
        echo "Not Found /etc/hosts.allow File" >> $RESULT_COLLECT_FILE 2>&1
        hosts_count=`expr $hosts_count + 1`
fi


if [ $hosts_count -ge 1 ]; then
        echo "[ U-18 ] : 취약" >> $RESULT_VALUE_FILE 2>&1
else
        echo "[ U-18 ] : 양호" >> $RESULT_VALUE_FILE 2>&1
fi

echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "====================== [U-18 접속 IP 및 포트 제한 START]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
}

function u19() {
################################################################################################
#
# - 주요 정보 통신 기반 시설 | 서비스 관리
# - U-19 finger 비활성화
#
################################################################################################

echo "[ U-19 ] : Check"
echo "====================== [U-19 finger 비활성화 START]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1

finger_count=0

echo "1. finger Package Check" >> $RESULT_COLLECT_FILE 2>&1

service_find="`rpm -qa | grep finger*`"
if [ "$service_find" != "" ]; then
	echo "$service_find" >> $RESULT_COLLECT_FILE 2>&1
else
	echo "Not Found Package" >> $RESULT_COLLECT_FILE 2>&1
fi

echo "" >> $RESULT_COLLECT_FILE 2>&1

echo "2. finger Command Check" >> $RESULT_COLLECT_FILE 2>&1

bin_find="`find /usr/*bin -name finger*`"
if [ "$bin_find" != "" ]; then
	echo "$bin_find" >> $RESULT_COLLECT_FILE 2>&1
else
	echo "Not Found Command" >> $RESULT_COLLECT_FILE 2>&1
fi

echo "" >> $RESULT_COLLECT_FILE 2>&1

echo "3. finger Source File Check" >> $RESULT_COLLECT_FILE 2>&1
conffile=`ps -ef | grep xinet | grep -v "grep" | awk -F-f '{print $2}' | sed 's/^ *//g'`

if [ "$conffile" = "" ]; then
	conffile=/etc/xinetd.conf
fi

if [ -f $conffile ]; then
	includedir="`cat $conffile | egrep -v '[#]|^$' | grep -i include | awk '{print $2}'`"
	filefind="`find $includedir -type f -exec ls {} \;`"

	for fingerfile in $filefind
	do
		finger_conf="`cat $fingerfile | egrep -v '[#]|^$' | grep -i finger`"
		finger_disable="`cat $fingerfile | egrep -v '[#]|^$' | grep -i disable | tail -30000 | grep -i disable | awk -F= '{print $2}' | sed 's/^ *//g' | grep -iv no`"
		if [ "$finger_conf" != "" ] && [ "$finger_disable" != "" ]; then
			finger_count=`expr $finger_count + 1`
			echo "$fingerfile" >> $RESULT_COLLECT_FILE 2>&1
		fi
	done
	
	if [ $finger_count -eq 0 ]; then
		echo "Not Found finger Source File" >> $RESULT_COLLECT_FILE 2>&1
	fi
else
	echo "Not Found Main Configuration File" >> $RESULT_COLLECT_FILE 2>&1
fi

if [ "$service_find" != "" ] || [ "$bin_find" != "" ] || [ $finger_count -gt 0 ]; then
	echo "[ U-19 ] : 취약" >> $RESULT_VALUE_FILE 2>&1
else
	echo "[ U-19 ] : 양호" >> $RESULT_VALUE_FILE 2>&1
fi

	
echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "====================== [U-19 finger 비활성화 END]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
}

function u20() {
################################################################################################
#
# - 주요 정보 통신 기반 시설 | 서비스 관리
# - U-20 Anonymous FTP 비활성화
#
################################################################################################

echo "[ U-20 ] : Check"
echo "====================== [U-20 Anonymous FTP 비활성화 START]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1

ftp_package="`rpm -qa vsftpd`"

if [ "$ftp_package" != "" ]; then

        conf_file=`ps -ef | grep vsftpd | grep -v "grep" | awk '{print $9}' | sed 's/^ *//g'`
        if [ "$conf_file" = "" ]; then
                conf_file=/etc/vsftpd/vsftpd.conf
        fi

        if [ -f $conf_file ]; then
                use_conf="`cat $conf_file | egrep -v '[#]|^$' | sed 's/^ *//g' | grep -i anonymous_enable`"
                if [ "$use_conf" != "" ]; then
                        anon_conf="`cat $conf_file | egrep -v '[#]|^$]' | sed 's/[ ]//g' | grep -i anonymous_enable=yes | awk -F= '{print $2}'`"
                        if [ "$anon_conf" != "" ]; then
                                echo "$use_conf" >> $RESULT_COLLECT_FILE 2>&1
                                echo "[ U-20 ] : 취약" >> $RESULT_VALUE_FILE 2>&1
                        else
                                echo "$use_conf" >> $RESULT_COLLECT_FILE 2>&1
                                echo "[ U-20 ] : 양호" >> $RESULT_VALUE_FILE 2>&1
                        fi
                else
                echo "Not Found Allow Anonymous Enable Configuration in the /etc/vsftpd/vsftp.conf" >> $RESULT_COLLECT_FILE 2>&1
                echo "[ U-20 ] : 양호" >> $RESULT_VALUE_FILE 2>&1
                fi
        else
                echo "Not Found FTP Configuration File" >> $RESULT_COLLECT_FILE 2>&1
        fi
else
        echo "Not Found FTP Service" >> $RESULT_COLLECT_FILE 2>&1
        echo "[ U-20 ] : 검토(or 미설치)" >> $RESULT_VALUE_FILE 2>&1
fi

echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "====================== [U-20 Anonymous FTP 비활성화 END]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
}

function u21() {
################################################################################################
#
# - 주요 정보 통신 기반 시설 | 서비스 관리
# - U-21 r 계열 서비스 비활성화
#
################################################################################################
echo "[ U-21 ] : Check"
echo "====================== [U-21 r 계열 서비스 비활성화 START]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1

r_count=0
echo "1. Xinetd Package Check" >> $RESULT_COLLECT_FILE 2>&1

xinetd_package="`rpm -qa xinetd`"
if [ "$xinetd_package" != "" ]; then
	echo "$xinetd_package" >> $RESULT_COLLECT_FILE 2>&1
else
	echo "Not Found Package" >> $RESULT_COLLECT_FILE 2>&1
fi

echo "" >> $RESULT_COLLECT_FILE 2>&1

echo "2. Xinetd Command Check" >> $RESULT_COLLECT_FILE 2>&1

bin_find="`find /usr/*bin -name xinetd*`"
if [ "$bin_find" != "" ]; then
	echo "$bin_find" >> $RESULT_COLLECT_FILE 2>&1
else
	echo "Not Found Command" >> $RESULT_COLLECT_FILE 2>&1
fi

if [ "$xinetd_package" != "" ] || [ "$bin_find" != "" ]; then
	echo "" >> $RESULT_COLLECT_FILE 2>&1
	echo "3. r Line Service File & Source File Check" >> $RESULT_COLLECT_FILE 2>&1
	conffile=`ps -ef | grep xinet | grep -v "grep" | awk -F-f '{print $2}' | sed 's/^ *//g'`
	if [ "$conffile" = "" ]; then
		conffile=/etc/xinetd.conf
	fi

	if [ -f $conffile ]; then
		includedir="`cat $conffile | egrep -v '[#]|^$' | grep -i include | awk '{print $2}'`"
		filefind="`find $includedir -type f -exec ls {} \;`"

		for rfile in $filefind
		do
			r_conf="`cat $rfile | egrep -v '[#]|^$' | egrep -i 'rsh|rlogin|rexec'`"
			r_disable="`cat $rfile | egrep -v '[#]|^$' | grep -i disable | tail -30000 | awk -F= '{print $2}' | sed 's/^ *//g' | grep -iv yes`"
			if [ "$r_conf" != "" ] && [ "$r_disable" != "" ]; then
				r_count=`expr $r_count + 1`
				echo "$rfile" >> $RESULT_COLLECT_FILE 2>&1
			fi
		done
	
		if [ $r_count -eq 0 ]; then
			echo "Not Found r Line Service File and Source File" >> $RESULT_COLLECT_FILE 2>&1
		fi
	else
		echo "Not Found Configuration File" >> $RESULT_COLLECT_FILE 2>&1
	fi
	if [ "$xinetd_package" != "" ] && [ "$bin_find" != "" ] && [ $r_count -gt 0 ]; then
		echo "[ U-21 ] : 취약" >> $RESULT_VALUE_FILE 2>&1
	else
		echo "[ U-21 ] : 양호" >> $RESULT_VALUE_FILE 2>&1
	fi
else
	echo "[ U-21 ] : 검토(or 미설치)" >> $RESULT_VALUE_FILE 2>&1
fi

echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "====================== [U-21 r 계열 서비스 비활성화 END]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
}

function u22() {
################################################################################################
#
# - 주요 정보 통신 기반 시설 | 서비스 관리
# - U-22 cron 파일 소유자 및 권한설정
#
################################################################################################

echo "[ U-22 ] : Check"
echo "====================== [U-22 cron 파일 소유자 및 권한설정 START]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1


if [ -f "/etc/cron.allow" ] || [ -f "/etc/cron.deny" ]; then
	cron_conffile="/etc/cron.allow /etc/cron.deny"
	cron_perm_count=0

	for i in $cron_conffile
	do
		if [ -f $i ]; then
			echo "`ls -l $i`" >> $RESULT_COLLECT_FILE 2>&1
			permission_val=`stat -c '%a' $i`
			owner_val=`stat -c '%U' $i`

			owner_perm_val=`echo "$permission_val" | awk '{ print substr($0, 1, 1) }'`
			group_perm_val=`echo "$permission_val" | awk '{ print substr($0, 2, 1) }'`
			other_perm_val=`echo "$permission_val" | awk '{ print substr($0, 3, 1) }'`

			if [ "$owner_perm_val" -le 6 ] && [ "$group_perm_val" -le 4 ] && [ "$other_perm_val" -le 0 ] && [ "$owner_val" = "root" ]; then
				cron_perm_count=`expr $cron_perm_count + 0`
			else
				cron_perm_count=`expr $cron_perm_count + 1`
			fi
		else
			echo "Not Found $i File" >> $RESULT_COLLECT_FILE 2>&1
		fi
	done
	if [ "$cron_perm_count" -eq 0 ]; then
		echo "[ U-22 ] : 양호" >> $RESULT_VALUE_FILE 2>&1
	else
		echo "[ U-22 ] : 취약" >> $RESULT_VALUE_FILE 2>&1
	fi
else
	echo "Not Found /etc/cron.allow And /etc/cron.deny File" >> $RESULT_COLLECT_FILE 2>&1
	echo "[ U-22 ] : 검토(or 미설치)" >> $RESULT_VALUE_FILE 2>&1
fi

echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "====================== [U-22 cron 파일 소유자 및 권한설정 END]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
}

function u23() {
################################################################################################
#
# - 주요 정보 통신 기반 시설 | 서비스 관리
# - U-23 Dos 공격에 취약한 서비스 비활성화
#
################################################################################################
echo "[ U-23 ] : Check"
echo "====================== [U-23 Dos 공격에 취약한 서비스 비활성화 START]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1

dos_count=0
echo "1. Xinetd Package Check" >> $RESULT_COLLECT_FILE 2>&1

xinetd_package="`rpm -qa xinetd`"
if [ "$xinetd_package" != "" ]; then
	echo "$xinetd_package" >> $RESULT_COLLECT_FILE 2>&1
else
	echo "Not Found Package" >> $RESULT_COLLECT_FILE 2>&1
fi

echo "" >> $RESULT_COLLECT_FILE 2>&1

echo "2. Xinetd Command Check" >> $RESULT_COLLECT_FILE 2>&1

bin_find="`find /usr/*bin -name xinetd*`"
if [ "$bin_find" != "" ]; then
	echo "$bin_find" >> $RESULT_COLLECT_FILE 2>&1
else
	echo "Not Found Command" >> $RESULT_COLLECT_FILE 2>&1
fi

if [ "$xinetd_package" != "" ] || [ "$bin_find" != "" ]; then
	echo "" >> $RESULT_COLLECT_FILE 2>&1
	echo "3. Vulnerable Service on the Dos Attack Check" >> $RESULT_COLLECT_FILE 2>&1
	conffile=`ps -ef | grep xinet | grep -v "grep" | awk -F-f '{print $2}' | sed 's/^ *//g'`
	if [ "$conffile" = "" ]; then
		conffile=/etc/xinetd.conf
	fi

	if [ -f $conffile ]; then
		includedir="`cat $conffile | egrep -v '[#]|^$' | grep -i include | awk '{print $2}'`"
		filefind="`find $includedir -type f -exec ls {} \;`"

		for dosfile in $filefind
		do
			dos_conf="`cat $dosfile | egrep -v '[#]|^$' | egrep -i 'echo|daytime|discard|chargen'`"
			dos_disable="`cat $dosfile | egrep -v '[#]|^$' | grep -i disable | tail -30000 | awk -F= '{print $2}' | sed 's/^ *//g' | grep -iv yes`"
			if [ "$dos_conf" != "" ] && [ "$dos_disable" != "" ]; then
				dos_count=`expr $dos_count + 1`
				echo "$dosfile" >> $RESULT_COLLECT_FILE 2>&1
			fi
		done
	
		if [ $dos_count -eq 0 ]; then
			echo "Not Found Vulnerable Service on the Dos Attack" >> $RESULT_COLLECT_FILE 2>&1
		fi
	else
		echo "Not Found Configuration File" >> $RESULT_COLLECT_FILE 2>&1
	fi
	if [ "$xinetd_package" != "" ] && [ "$bin_find" != "" ] && [ $dos_count -gt 0 ]; then
		echo "[ U-23 ] : 취약" >> $RESULT_VALUE_FILE 2>&1
	else
		echo "[ U-23 ] : 양호" >> $RESULT_VALUE_FILE 2>&1
	fi
else
	echo "[ U-23 ] : 검토(or 미설치)" >> $RESULT_VALUE_FILE 2>&1
fi

echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "====================== [U-23 Dos 공격에 취약한 서비스 비활성화 END]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
}

function u24() {
################################################################################################
#
# - 주요 정보 통신 기반 시설 | 서비스 관리
# - U-24 NFS 서비스 비활성화
#
################################################################################################

echo "[ U-24 ] : Check"
echo "====================== [U-24 NFS 서비스 비활성화 START]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "1. NFS Process Check" >> $RESULT_COLLECT_FILE 2>&1
nfs_process=`ps -ef | grep -v "grep" | grep "nfsd"`
if [ "$nfs_process" != "" ]; then
	echo "$nfs_process" >> $RESULT_COLLECT_FILE 2>&1
else
	echo "Not Found Process" >> $RESULT_COLLECT_FILE 2>&1
fi

echo "" >> $RESULT_COLLECT_FILE 2>&1

echo "2. NFS Service Check" >> $RESULT_COLLECT_FILE 2>&1
if [ "$systemctl_cmd" != "" ]; then
	nfs_service=`$systemctl_cmd list-units --type service | grep 'nfs-mountd\.service' | sed -e 's/^ *//g' -e 's/^	*//g' | tr -s " \t"`
	if [ "$nfs_service" != "" ]; then
		echo "$nfs_service" >> $RESULT_COLLECT_FILE 2>&1
	else
		echo "Not Found Service" >> $RESULT_COLLECT_FILE 2>&1
	fi
else
	echo "Not Found systemctl Command" >> $RESULT_COLLECT_FILE 2>&1
fi

if [ "$nfs_process" != "" ] || [ "$nfs_service" != "" ]; then
	echo "[ U-24 ] : 취약" >> $RESULT_VALUE_FILE 2>&1
else
	echo "[ U-24 ] : 양호" >> $RESULT_VALUE_FILE 2>&1
fi
echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "====================== [U-24 NFS 서비스 비활성화 END]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
}

function u25() {
################################################################################################
#
# - 주요 정보 통신 기반 시설 | 서비스 관리
# - U-25 NFS 접근통제
#
################################################################################################

echo "[ U-25 ] : Check"
echo "====================== [U-25 NFS 접근통제 START]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "1. NFS Process Check" >> $RESULT_COLLECT_FILE 2>&1
nfs_process=`ps -ef | grep -v "grep" | grep "nfsd"`
if [ "$nfs_process" != "" ]; then
        echo "$nfs_process" >> $RESULT_COLLECT_FILE 2>&1
else
        echo "Not Found Process" >> $RESULT_COLLECT_FILE 2>&1
fi

echo "" >> $RESULT_COLLECT_FILE 2>&1

echo "2. NFS Service Check" >> $RESULT_COLLECT_FILE 2>&1
if [ "$systemctl_cmd" != "" ]; then
        nfs_service=`$systemctl_cmd list-units --type service | grep 'nfs-mountd\.service' | sed -e 's/^ *//g' -e 's/^  *//g' | tr -s " \t"`
        if [ "$nfs_service" != "" ]; then
                echo "$nfs_service" >> $RESULT_COLLECT_FILE 2>&1
        else
                echo "Not Found Service" >> $RESULT_COLLECT_FILE 2>&1
        fi
else
        echo "Not Found systemctl Command" >> $RESULT_COLLECT_FILE 2>&1
fi

echo "" >> $RESULT_COLLECT_FILE 2>&1

echo "3. /etc/exports File Check" >> $RESULT_COLLECT_FILE 2>&1

if [ -f "/etc/exports" ]; then
	exports_file="`cat /etc/exports | egrep -v '^#|^$' | grep \* | sed -n p`"
	if [ "$exports_file" != "" ]; then
		echo "$exports_file" >> $RESULT_COLLECT_FILE 2>&1
		if [ "$nfs_process" != "" ] || [ "$nfs_service" != "" ]; then
			echo "[ U-25 ] : 취약" >> $RESULT_VALUE_FILE 2>&1
		else
			echo "[ U-25 ] : 양호" >> $RESULT_VALUE_FILE 2>&1
		fi
	else
		echo "[ U-25 ] : 양호" >> $RESULT_VALUE_FILE 2>&1
		echo "Not Found NFS Everyone Shared Configuration" >> $RESULT_COLLECT_FILE 2>&1
	fi
else
	echo "Not Found /etc/exports File" >> $RESULT_COLLECT_FILE 2>&1
	echo "[ U-25 ] : 양호" >> $RESULT_VALUE_FILE 2>&1
fi
echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "====================== [U-25 NFS 접근통제 END]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
}

function u26() {
################################################################################################
#
# - 주요 정보 통신 기반 시설 | 서비스 관리
# - U-26 automountd 제거
#
################################################################################################
echo "[ U-26 ] : Check"
echo "====================== [U-26 automountd 제거 START]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1

auto_process=`ps -ef | grep automount | grep -v grep`
if [ "$auto_process" != "" ]; then
        echo "$auto_process" >> $RESULT_COLLECT_FILE 2>&1
        echo "[ U-26 ] : 취약" >> $RESULT_VALUE_FILE 2>&1
else
        echo "Not Found Automountd Process" >> $RESULT_COLLECT_FILE 2>&1
        echo "[ U-26 ] : 양호" >> $RESULT_VALUE_FILE 2>&1
fi

echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "====================== [U-26 automountd 제거 END]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
}

function u27() {
################################################################################################
#
# - 주요 정보 통신 기반 시설 | 서비스 관리
# - U-27 RPC 서비스 확인
#
################################################################################################
echo "[ U-27 ] : Check"
echo "====================== [U-27 RPC 서비스 확인 START]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1

rpc_count=0
echo "1. Xinetd Package Check" >> $RESULT_COLLECT_FILE 2>&1

xinetd_package="`rpm -qa xinetd`"
if [ "$xinetd_package" != "" ]; then
	echo "$xinetd_package" >> $RESULT_COLLECT_FILE 2>&1
else
	echo "Not Found Package" >> $RESULT_COLLECT_FILE 2>&1
fi

echo "" >> $RESULT_COLLECT_FILE 2>&1

echo "2. Xinetd Command Check" >> $RESULT_COLLECT_FILE 2>&1

bin_find="`find /usr/*bin -name xinetd*`"
if [ "$bin_find" != "" ]; then
	echo "$bin_find" >> $RESULT_COLLECT_FILE 2>&1
else
	echo "Not Found Command" >> $RESULT_COLLECT_FILE 2>&1
fi

if [ "$xinetd_package" != "" ] || [ "$bin_find" != "" ]; then
	echo "" >> $RESULT_COLLECT_FILE 2>&1
	echo "3. RPC Service File Check" >> $RESULT_COLLECT_FILE 2>&1
	conffile=`ps -ef | grep xinet | grep -v "grep" | awk -F-f '{print $2}' | sed 's/^ *//g'`
	if [ "$conffile" = "" ]; then
		conffile=/etc/xinetd.conf
	fi

	if [ -f $conffile ]; then
		includedir="`cat $conffile | egrep -v '[#]|^$' | grep -i include | awk '{print $2}'`"
		filefind="`find $includedir -type f -exec ls {} \;`"

		for rpcfile in $filefind
		do
			rpc_conf="`cat $rpcfile | egrep -v '[#]|^$' | egrep -i 'rsh|rlogin|rexec'`"
			rpc_disable="`cat $rpcfile | egrep -v '[#]|^$' | grep -i disable | tail -30000 | awk -F= '{print $2}' | sed 's/^ *//g' | grep -iv yes`"
			if [ "$rpc_conf" != "" ] && [ "$rpc_disable" != "" ]; then
				rpc_count=`expr $rpc_count + 1`
				echo "$rpcfile" >> $RESULT_COLLECT_FILE 2>&1
			fi
		done
	
		if [ $rpc_count -eq 0 ]; then
			echo "Not Found RPC Service File" >> $RESULT_COLLECT_FILE 2>&1
		fi
	else
		echo "Not Found Configuration File" >> $RESULT_COLLECT_FILE 2>&1
	fi
	if [ "$xinetd_package" != "" ] && [ "$bin_find" != "" ] && [ $rpc_count -gt 0 ]; then
		echo "[ U-27 ] : 취약" >> $RESULT_VALUE_FILE 2>&1
	else
		echo "[ U-27 ] : 양호" >> $RESULT_VALUE_FILE 2>&1
	fi
else
	echo "[ U-27 ] : 검토(or 미설치)" >> $RESULT_VALUE_FILE 2>&1
fi

echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "====================== [U-27 RPC 서비스 확인 END]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
}

function u28() {
################################################################################################
#
# - 주요 정보 통신 기반 시설 | 서비스 관리
# - U-28 NIS, NIS+ 점검
#
################################################################################################
echo "[ U-28 ] : Check"
echo "====================== [U-28 NIS, NIS+ 점검 START]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1

nis_process=`ps -ef | egrep 'ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated' | grep -v grep`
if [ "$nis_process" != "" ]; then
        echo "$nis_process" >> $RESULT_COLLECT_FILE 2>&1
        echo "[ U-28 ] : 취약" >> $RESULT_VALUE_FILE 2>&1
else
        echo "Not Found NIS, NIS+ Process" >> $RESULT_COLLECT_FILE 2>&1
        echo "[ U-28 ] : 양호" >> $RESULT_VALUE_FILE 2>&1
fi

echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "====================== [U-28 NIS, NIS+ 점검 END]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
}

function u29() {
################################################################################################
#
# - 주요 정보 통신 기반 시설 | 서비스 관리
# - U-29 tftp, talk 서비스 비활성화
#
################################################################################################
echo "[ U-29 ] : Check"
echo "====================== [U-29 tftp, talk 서비스 비활성화 START]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1

t_count=0
echo "1. TFTP Process Check" >> $RESULT_COLLECT_FILE 2>&1
tftp_process=`ps -ef | grep tftp | grep -v grep`

if [ "$tftp_process" != "" ]; then
	echo "$tftp_process" >> $RESULT_COLLECT_FILE 2>&1
else
	echo "Not Found TFTP Process" >> $RESULT_COLLECT_FILE 2>&1
fi

echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "2. Talk Process Check" >> $RESULT_COLLECT_FILE 2>&1
talk_process=`ps -ef | grep talk | grep -v grep`

if [ "$talk_process" != "" ]; then
	echo "talk_process" >> $RESULT_COLLECT_FILE 2>&1
else
	echo "Not Found Talk Process" >> $RESULT_COLLECT_FILE 2>&1
fi

echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "3. Xinetd Process & TFTP,Talk Source File Check" >> $RESULT_COLLECT_FILE 2>&1
xinetd_process=`ps -ef | grep xinetd | grep -v grep`

if [ "$xinetd_process" != "" ]; then
	conffile=`ps -ef | grep xinet | grep -v "grep" | awk -F-f '{print $2}' | sed 's/^ *//g'`
	if [ "$conffile" = "" ]; then
		conffile=/etc/xinetd.conf	
		if [ -f $conffile ]; then
			include_dir="`cat $conffile | egrep -v '[#]|^$' | grep -i include | awk '{print $2}'`"
			file_list="`find $include_dir -type f -exec ls {} \;`"
			for files in $file_list
			do
				tftp_talk_conf="`cat $files | egrep '[#]|^$' | egrep -i 'tftp|talk'`"
				tftp_talk_disable="`cat $files | egrep '[#]|^$' | grep -i disable | tail -30000 | awk -F= '{print $2}' | sed 's/^ *//g' | grep -iv yes`"
				if [ "$tftp_talk_conf" != "" ] && [ "$tftp_talk_disable" != "" ]; then
					t_count=`expr $t_count + 1`
					echo "$files" >> $RESULT_COLLECT_FILE 2>&1
				fi
			done
			if [ $t_count -eq 0 ]; then
				echo "Not Found TFTP & Talk Source File" >> $RESULT_COLLECT_FILE 2>&1
			fi
		else
			echo "Not Found Configuration File Include Directory" >> $RESULT_COLLECT_FILE 2>&1
		fi
	else
		echo "Not Found Configuration File" >> $RESULT_COLLECT_FILE 2>&1	
	fi
else
	echo "Not Found Process" >> $RESULT_COLLECT_FILE 2>&1
fi

if [ "$tftp_process" != "" ] || [ "$talk_process" != "" ] || [ $t_count -gt 0 ]; then
	echo "[ U-29 ] : 취약" >> $RESULT_VALUE_FILE 2>&1
else
	echo "[ U-29 ] : 양호" >> $RESULT_VALUE_FILE 2>&1
fi
	

echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "====================== [U-29 tftp, talk 서비스 비활성화 END]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
}

function u30() {
################################################################################################
#
# - 주요 정보 통신 기반 시설 | 서비스 관리
# - U-30 Sendmail 버전 점검
#
################################################################################################

echo "[ U-30 ] : Check"
echo "====================== [U-30 Sendmail 버전 점검 START]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
SDMAIL=`rpm -qa sendmail`

if [ "$SDMAIL" != "" ]; then
	Yumck=`yum check-updates 2>/dev/null | egrep -i ^sendmail | awk '{print $3}'`
    	if [ "$Yumck" != "" ]; then
        	echo "[ U-30 ] : 취약" >> $RESULT_VALUE_FILE 2>&1
      	  	echo "$SDMAIL" >> $RESULT_COLLECT_FILE 2>&1
	else
        	echo "[ U-30 ] : 양호" >> $RESULT_VALUE_FILE 2>&1
        	echo "$SDMAIL" >> $RESULT_COLLECT_FILE 2>&1
    	fi
else
    	echo "[ U-30 ] : 검토(or 미설치)" >> $RESULT_VALUE_FILE 2>&1
    	echo "Not Found Sendmail Service" >> $RESULT_COLLECT_FILE 2>&1
fi
echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "====================== [U-30 Sendmail 버전 점검 END]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
}

function u31() {
################################################################################################
#
# - 주요 정보 통신 기반 시설 | 서비스 관리
# - U-31 스팸 메일 릴레이 제한
#
################################################################################################

echo "[ U-31 ] : Check"
echo "====================== [U-31 스팸 메일 릴레이 제한 START]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1

echo "1. Sendmail Process Check" >> $RESULT_COLLECT_FILE 2>&1
get_sendmail_ps=`ps -ef | grep -v "grep" | grep "sendmail"`
if [ "$get_sendmail_ps" != "" ]; then
	echo "$get_sendmail_ps" >> $RESULT_COLLECT_FILE 2>&1
else
	echo "Not Found Process" >> $RESULT_COLLECT_FILE 2>&1
fi
echo "" >> $RESULT_COLLECT_FILE 2>&1

echo "2. Sendmail Service Check" >> $RESULT_COLLECT_FILE 2>&1
if [ "$systemctl_cmd" != "" ]; then
	get_sendmail_service=`$systemctl_cmd list-units --type service | grep 'sendmail\.service' | sed -e 's/^ *//g' -e 's/^	*//g' | tr -s " \t"`
	if [ "$get_sendmail_service" != "" ]; then
		echo "$get_sendmail_service" >> $RESULT_COLLECT_FILE 2>&1
	else
		echo "Not Found Service" >> $RESULT_COLLECT_FILE 2>&1
	fi
else
	echo "Not Found systemctl Command" >> $RESULT_COLLECT_FILE 2>&1
fi

if [ "$get_sendmail_ps" != "" ] || [ "$get_sendmail_service" != "" ]; then
	echo "" >> $RESULT_COLLECT_FILE 2>&1
	echo "3. Sendmail Configuration Check" >> $RESULT_COLLECT_FILE 2>&1

	if [ -f "/etc/mail/sendmail.cf" ]; then
		sendmail_file="/etc/mail/sendmail.cf"
	elif [ -f "/etc/sendmail.cf" ]; then
		sendmail_file="/etc/sendmail.cf"
	fi

	if [ "$sendmail_file" != "" ]; then
		echo "- $sendmail_file" >> $RESULT_COLLECT_FILE 2>&1
		get_sendmail_conf=`cat "$sendmail_file" | egrep -v '^#|^$' | egrep -i "R$\*|Relaying\sdenied"`
		if [ "$get_sendmail_conf" != "" ]; then
			echo "$get_sendmail_conf" >> $RESULT_COLLECT_FILE 2>&1
			echo "[ U-31 ] : 양호" >> $RESULT_VALUE_FILE 2>&1
		else
			echo "Not Found Spam Relay Configuration" >> $RESULT_COLLECT_FILE 2>&1
			echo "[ U-31 ] : 취약" >> $RESULT_VALUE_FILE 2>&1
		fi
	else
		echo "Not Found Sendmail Configuration File" >> $RESULT_COLLECT_FILE 2>&1
	fi
else
	echo "[ U-31 ] : 검토(or 미설치)" >> $RESULT_VALUE_FILE 2>&1
	
fi

echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "====================== [U-31 스팸 메일 릴레이 제한 END]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
}

function u32() {
################################################################################################
#
# - 주요 정보 통신 기반 시설 | 서비스 관리
# - U-32 일반 사용자의 Sendmail 실행 방지
#
################################################################################################

echo "[ U-32 ] : Check"
echo "====================== [U-32 일반 사용자의 Sendmail 실행 방지 START]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1

echo "1. Sendmail Process Check" >> $RESULT_COLLECT_FILE 2>&1
get_sendmail_ps=`ps -ef | grep -v "grep" | grep "sendmail"`
if [ "$get_sendmail_ps" != "" ]; then
	echo "$get_sendmail_ps" >> $RESULT_COLLECT_FILE 2>&1
else
	echo "Not Found Process" >> $RESULT_COLLECT_FILE 2>&1
fi
echo "" >> $RESULT_COLLECT_FILE 2>&1

echo "2. Sendmail Service Check" >> $RESULT_COLLECT_FILE 2>&1
if [ "$systemctl_cmd" != "" ]; then
	get_sendmail_service=`$systemctl_cmd list-units --type service | grep 'sendmail\.service' | sed -e 's/^ *//g' -e 's/^	*//g' | tr -s " \t"`
	if [ "$get_sendmail_service" != "" ]; then
		echo "$get_sendmail_service" >> $RESULT_COLLECT_FILE 2>&1
	else
		echo "Not Found Service" >> $RESULT_COLLECT_FILE 2>&1
	fi
else
	echo "Not Found systemctl Command" >> $RESULT_COLLECT_FILE 2>&1
fi

if [ "$get_sendmail_ps" != "" ] || [ "$get_sendmail_service" != "" ]; then
	echo "" >> $RESULT_COLLECT_FILE 2>&1
	echo "3. Sendmail Configuration Check" >> $RESULT_COLLECT_FILE 2>&1

	if [ -f "/etc/mail/sendmail.cf" ]; then
		sendmail_file="/etc/mail/sendmail.cf"
	elif [ -f "/etc/sendmail.cf" ]; then
		sendmail_file="/etc/sendmail.cf"
	fi

	if [ "$sendmail_file" != "" ]; then
		echo "- $sendmail_file" >> $RESULT_COLLECT_FILE 2>&1
		get_sendmail_conf=`cat "$sendmail_file" | egrep -v '^#|^$' | grep -i "PrivacyOptions" | grep -i "restrictqrun"`
		if [ "$get_sendmail_conf" != "" ]; then
			echo "$get_sendmail_conf" >> $RESULT_COLLECT_FILE 2>&1
			echo "[ U-32 ] : 양호" >> $RESULT_VALUE_FILE 2>&1
		else
			echo "Not Found PrivacyOptions restrictqrun Configuration" >> $RESULT_COLLECT_FILE 2>&1
			echo "[ U-32 ] : 취약" >> $RESULT_VALUE_FILE 2>&1
		fi
	else
		echo "Not Found Sendmail Configuration File" >> $RESULT_COLLECT_FILE 2>&1
	fi
else
	echo "[ U-32 ] : 검토(or 미설치)" >> $RESULT_VALUE_FILE 2>&1
fi

echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "====================== [U-32 일반 사용자의 Sendmail 실행 방지 END]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
}

function u33() {
################################################################################################
#
# - 주요 정보 통신 기반 시설 | 서비스 관리
# - U-33 DNS 보안 버전 패치
#
################################################################################################
echo "[ U-33 ] : Check"
echo "====================== [U-33 DNS 보안 버전 패치 START]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
RPM=`rpm -qa bind`
Yumck=`yum check-updates 2>/dev/null | egrep -i ^bind | awk '{print $3}'`

if [ "$RPM" != "" ]; then
    	if [ "$Yumck" != "" ]; then
        	echo "[ U-33 ] : 취약" >> $RESULT_VALUE_FILE 2>&1
    		echo "$RPM" >> $RESULT_COLLECT_FILE 2>&1
    	else
        	echo "[ U-33 ] : 양호" >> $RESULT_VALUE_FILE 2>&1
    		echo "$RPM" >> $RESULT_COLLECT_FILE 2>&1
    	fi
else
    	echo "[ U-33 ] : 검토(or 미설치)" >> $RESULT_VALUE_FILE 2>&1
    	echo "Not Found DNS Service" >> $RESULT_COLLECT_FILE 2>&1
fi
echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "====================== [U-33 DNS 보안 버전 패치 END]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
}

function u34() {
################################################################################################
#
# - 주요 정보 통신 기반 시설 | 서비스 관리
# - U-34 DNS Zone Tranfer 설정
#
################################################################################################
echo "[ U-34 ] : Check"
echo "====================== [U-34 DNS Zone Transfer 설정 START]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1

RPM=`rpm -qa bind`

if [ "$RPM" != "" ]; then
        NAMEPATH=`ps -ef | grep named | grep -v grep | awk -F -c '{print $2}' | sed 's/^ *//g'`
        if [ "$NAMEPATH" == "" ]; then
                NAMEPATH=/etc/named.conf
        fi

        RFCPATH=`cat $NAMEPATH | egrep -i include | grep -v "^#|^$" | awk -F \" '{print $2}' | sed 's/";//g' | grep -v root`
        TRANS=`cat $RFCPATH | egrep -v '[#]|^$' | grep -i allow-transfer`
        if [ "$TRANS" != "" ]; then
                ANYCNT=`cat $RFCPATH | egrep -v '[#]|^$' | grep -i allow-transfer | awk '{for(i=1;i<=NF;i++) {if($i == "any;"||$i == "ANY;"||$i == "Any;") {print $i}}}'`
                if [ "$ANYCNT" != "" ]; then
                        echo "[ U-34 ] : 취약" >> $RESULT_VALUE_FILE 2>&1
                        echo "$TRANS" >> $RESULT_COLLECT_FILE 2>&1
                else
                        echo "[ U-34 ] : 양호" >> $RESULT_VALUE_FILE 2>&1
                        echo "$TRANS" >> $RESULT_COLLECT_FILE 2>&1
                fi
        else
                echo "[ U-34 ] : 양호" >> $RESULT_VALUE_FILE 2>&1
                echo "Not Found Allow-Transfer Configuration" >> $RESULT_COLLECT_FILE 2>&1
        fi
else
        echo "[ U-34 ] : 검토(or 미설치)" >> $RESULT_VALUE_FILE 2>&1
        echo "Not Found DNS Service" >> $RESULT_COLLECT_FILE 2>&1
fi

echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "====================== [U-34 DNS Zone Transfer 설정 END]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
}

function u35() {
################################################################################################
#
# - 주요 정보 통신 기반 시설 | 서비스 관리
# - U-35 Apache 디렉토리 리스팅 제거
#
################################################################################################
echo "[ U-35 ] : Check"
echo "====================== [U-35 Apache 디렉토리 리스팅 제거 START]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1

indexes_count=0

http_package="`rpm -qa httpd`"

if [ "$http_package" != "" ]; then
	
	homeroot="`httpd -V 2>&1 | grep -v AH00558 | grep HTTPD_ROOT | awk -F= '{print $2}' | sed 's/["]//g'`"
	main_conffile="`httpd -V 2>&1 | grep -v AH00558 | egrep 'HTTPD_ROOT|SERVER_CONFIG_FILE' | awk -F= '{print $2}' | sed 's/["/]/ /g' | awk '{for(i=1;i<=NF;i++) {printf "/%s", $i}}'`"

	if [ -f $main_conffile ]; then

		include_option="`cat $main_conffile | egrep -v '[#]' | grep -i includeoptional | awk '{print $2}' | awk -F/ '{for(i=1;i<NF;i++) {printf "%s\n" , $i }}'`"
		include_dir="`awk -v home=$homeroot -v dir=$include_option 'BEGIN {printf "%s/%s", home , dir}'`"
		conf_find="`find $include_dir ! \( -name welcom* -o -name manual* -o -name autoindex* \) -name *.conf -type f -exec ls {} \;`"

		echo "- $main_conffile" >> $RESULT_COLLECT_FILE 2>&1
		echo "" >> $RESULT_COLLECT_FILE 2>&1
		main_indexes="`cat $main_conffile | egrep -v '[#]|^$' | grep -i option | grep -i indexes | sed 's/^ *//g'`"
		if [ "$main_indexes" != "" ]; then
			dir_indexes="`cat $main_conffile | egrep -v '[#]|^$' | grep -iv directoryindex | egrep -i 'directory|indexes' | tail -30000`"
			echo "$dir_indexes" >> $RESULT_COLLECT_FILE 2>&1
			echo "" >> $RESULT_COLLECT_FILE 2>&1
			indexes_count=`expr $indexes_count + 1`
		else
			echo "Not Found Indexes Configuration" >> $RESULT_COLLECT_FILE 2>&1
			echo "" >> $RESULT_COLLECT_FILE 2>&1
		fi
	else
		echo "Not Found Httpd Main Configuration File" >> $RESULT_COLLECT_FILE 2>&1
		echo "" >> $RESULT_COLLECT_FILE 2>&1
	fi

	
	if [ -d $include_dir ]; then
		if [ "$conf_find" != "" ]; then		
			for conf_file in $conf_find
			do
				echo "- $conf_file"  >> $RESULT_COLLECT_FILE 2>&1
				echo "" >> $RESULT_COLLECT_FILE 2>&1
				indexes_conf="`cat $conf_file | egrep -v '[#]|^$' | grep -i option | grep -i indexes | sed 's/^ *//g'`"
				if [ "$indexes_conf" != "" ]; then
					dir_indexes="`cat $conf_file | egrep -v '[#]|^$' | grep -iv directoryindex | egrep -i 'directory|indexes' | tail -30000`"
					echo "$dir_indexes" >> $RESULT_COLLECT_FILE 2>&1
					echo "" >> $RESULT_COLLECT_FILE 2>&1
					indexes_count=`expr $indexes_count + 1`
				else
					echo "Not Found Indexes Configuration" >> $RESULT_COLLECT_FILE 2>&1
					echo "" >> $RESULT_COLLECT_FILE 2>&1
				fi
			done
		else
			echo "Not Found Included Configuration File" >> $RESULT_COLLECT_FILE 2>&1
			echo "" >> $RESULT_COLLECT_FILE 2>&1
		fi
	else
		echo "Not Found Directory in the Including Conf Files" >> $RESULT_COLLECT_FILE 2>&1
		echo "" >> $RESULT_COLLECT_FILE 2>&1
	fi	

	if [ $indexes_count -gt 0 ]; then
		echo "[ U-35 ] : 취약" >> $RESULT_VALUE_FILE 2>&1
	else
		echo "[ U-35 ] : 양호" >> $RESULT_VALUE_FILE 2>&1
	fi

else
	echo "Not Found Httpd Service" >> $RESULT_COLLECT_FILE 2>&1
	echo "" >> $RESULT_COLLECT_FILE 2>&1
	echo "[ U-35 ] : 검토(or 미설치)" >> $RESULT_VALUE_FILE 2>&1
fi
echo "====================== [U-35 Apache 디렉토리 리스팅 제거 END]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
}

function u36() {
################################################################################################
#
# - 주요 정보 통신 기반 시설 | 서비스 관리
# - U-36 Apache 웹 프로세스 권한 제한
#
################################################################################################
echo "[ U-36 ] : Check"
echo "====================== [U-36 Apache 웹 프로세스 권한 제한 START]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1

http_package="`rpm -qa httpd`"

if [ "$http_package" != "" ]; then

	main_conffile="`httpd -V 2>&1 | grep -v AH00558 | egrep 'HTTPD_ROOT|SERVER_CONFIG_FILE' | awk -F= '{print $2}' | sed 's/["/]/ /g' | awk '{for(i=1;i<=NF;i++) {printf "/%s", $i}}'`"

	if [ -f $main_conffile ]; then
		apache_uid="`cat $main_conffile | egrep -v '[#]|^$' | grep -i user | grep -iv logformat | sed 's/^    //g'`"
		apache_gid="`cat $main_conffile | egrep -v '[#]|^$' | grep -i group | grep -iv logformat | sed 's/^    //g'`"
		echo "$apache_uid" >> $RESULT_COLLECT_FILE 2>&1
		echo "$apache_gid" >> $RESULT_COLLECT_FILE 2>&1
		if [ "`echo $apache_uid | awk '{print $3}'`" == "root" ] || [ "`echo $apache_gid | awk '{print $3}'`" == "root" ]; then
			echo "[ U-36 ] : 취약" >> $RESULT_VALUE_FILE 2>&1
		else
			echo "[ U-36 ] : 양호" >> $RESULT_VALUE_FILE 2>&1
		fi
	else
        	echo "Not Found Httpd Main Configuration File" >> $RESULT_COLLECT_FILE 2>&1
        	echo "[ U-36 ] : 검토(or 미설치)" >> $RESULT_VALUE_FILE 2>&1
	fi

else
	        echo "Not Found Httpd Service" >> $RESULT_COLLECT_FILE 2>&1
        	echo "[ U-36 ] : 검토(or 미설치)" >> $RESULT_VALUE_FILE 2>&1
fi
echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "====================== [U-36 Apache 웹 프로세스 권한 제한 END]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
}

function u37() {
################################################################################################
#
# - 주요 정보 통신 기반 시설 | 서비스 관리
# - U-37 Apache 상위 디렉토리 접근 금지
#
################################################################################################
echo "[ U-37 ] : Check"
echo "====================== [U-37 Apache 상위 디렉토리 접근 금지 START]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1

override_count=0
http_package="`rpm -qa httpd`"

if [ "$http_package" != "" ]; then

	homeroot="`httpd -V 2>&1 | grep -v AH00558 | grep HTTPD_ROOT | awk -F= '{print $2}' | sed 's/["]//g'`"
	main_conffile="`httpd -V 2>&1 | grep -v AH00558 | egrep 'HTTPD_ROOT|SERVER_CONFIG_FILE' | awk -F= '{print $2}' | sed 's/["/]/ /g' | awk '{for(i=1;i<=NF;i++) {printf "/%s", $i}}'`"

	if [ -f $main_conffile ]; then

		include_option="`cat $main_conffile | egrep -v '[#]' | grep -i includeoptional | awk '{print $2}' | awk -F/ '{for(i=1;i<NF;i++) {printf "%s\n" , $i }}'`"
		include_dir="`awk -v home=$homeroot -v dir=$include_option 'BEGIN {printf "%s/%s", home , dir}'`"
		conf_find="`find $include_dir ! \( -name welcom* -o -name manual* -o -name autoindex* \) -name *.conf -type f -exec ls {} \;`"

		override_conf="`cat $main_conffile | egrep -v '[#]|^$' | grep -i allowoverride | sed 's/^ *//g' | grep -i none`"

		echo "- $main_conffile" >> $RESULT_COLLECT_FILE 2>&1
		echo "" >> $RESULT_COLLECT_FILE 2>&1
		if [ "$override_conf" != "" ]; then
			dir_override="`cat $main_conffile | egrep -v '[#]|^$' | egrep -i 'directory|allowoverride' | tail -30000`"
			echo "$dir_override" >> $RESULT_COLLECT_FILE 2>&1
			override_count=`expr $override_count + 1`
			echo "" >> $RESULT_COLLECT_FILE 2>&1
		else
			echo "Not Found AllowOverride Configuration" >> $RESULT_COLLECT_FILE 2>&1
			echo "" >> $RESULT_COLLECT_FILE 2>&1
		fi
	else
		echo "Not Found Httpd Main Configuration File" >> $RESULT_COLLECT_FILE 2>&1
		echo "" >> $RESULT_COLLECT_FILE 2>&1
	fi

	
	if [ -d $include_dir ]; then
		if [ "$conf_find" != "" ]; then		
			for conf_file in $conf_find
			do
				echo "- $conf_file"  >> $RESULT_COLLECT_FILE 2>&1
				echo "" >> $RESULT_COLLECT_FILE 2>&1
				override_conf="`cat $conf_file | egrep -v '[#]|^$' | grep -i allowoverride | sed 's/^ *//g' | grep -i none`"
				if [ "$override_conf" != "" ]; then
					dir_override="`cat $conf_file | egrep -v '[#]|^$' | egrep -i 'directory|allowoverride' | tail -30000`"
					echo "$dir_override" >> $RESULT_COLLECT_FILE 2>&1
					echo "" >> $RESULT_COLLECT_FILE 2>&1
					override_count=`expr $override_count + 1`
				else
					echo "Not Found AllowOverride Configuration" >> $RESULT_COLLECT_FILE 2>&1
					echo "" >> $RESULT_COLLECT_FILE 2>&1
				fi
			done
		else
			echo "Not Found Included Configuration File" >> $RESULT_COLLECT_FILE 2>&1
			echo "" >> $RESULT_COLLECT_FILE 2>&1
		fi
	else
		echo "Not Found Directory in the Including Conf Files" >> $RESULT_COLLECT_FILE 2>&1
		echo "" >> $RESULT_COLLECT_FILE 2>&1
	fi	

	if [ $override_count -gt 0 ]; then
		echo "[ U-37 ] : 취약" >> $RESULT_VALUE_FILE 2>&1
	else
		echo "[ U-37 ] : 양호" >> $RESULT_VALUE_FILE 2>&1
	fi

else
	echo "Not Found Httpd Service" >> $RESULT_COLLECT_FILE 2>&1
	echo "" >> $RESULT_COLLECT_FILE 2>&1
	echo "[ U-37 ] : 검토(or 미설치)" >> $RESULT_VALUE_FILE 2>&1
fi
echo "====================== [U-37 Apache 상위 디렉토리 접근 금지 END]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
}

function u38() {
################################################################################################
#
# - 주요 정보 통신 기반 시설 | 서비스 관리
# - U-38 Apache 불필요한 파일 제거
#
################################################################################################
echo "[ U-38 ] : Check"
echo "====================== [U-38 Apache 불필요한 파일 제거 START]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1

http_package="`rpm -qa httpd`"

if [ "$http_package" != "" ]; then

        main_conffile="`httpd -V 2>&1 | grep -v AH00558 | egrep 'HTTPD_ROOT|SERVER_CONFIG_FILE' | awk -F= '{print $2}' | sed 's/["/]/ /g' | awk '{for(i=1;i<=NF;i++) {printf "/%s", $i}}'`"
	home_root="`httpd -V 2>&1 | grep -v AH00558 | grep HTTPD_ROOT | awk -F= '{print $2}' | sed 's/["]//g'`"
	manual_find="`find $home_root -type f -name manual* -exec ls -la {} \;`"

        if [ "$manual_find" != "" ]; then
		echo "[ U-38 ] : 취약" >> $RESULT_VALUE_FILE 2>&1
		echo "$manual_find" >> $RESULT_COLLECT_FILE 2>&1
	else
		echo "[ U-38 ] : 양호" >> $RESULT_VALUE_FILE 2>&1
		echo "Not Found Unnecessary Files" >> $RESULT_COLLECT_FILE 2>&1
	fi
else
        echo "Not Found Httpd Service" >> $RESULT_COLLECT_FILE 2>&1
        echo "[ U-38 ] : 검토(or 미설치)" >> $RESULT_VALUE_FILE 2>&1
fi
echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "====================== U-38 Apache 불필요한 파일 제거 END]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
}

function u39() {
################################################################################################
#
# - 주요 정보 통신 기반 시설 | 서비스 관리
# - U-39 Apache 링크 사용 금지
#
################################################################################################
echo "[ U-39 ] : Check"
echo "====================== [U-39 Apache 링크 사용 금지 START]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1

symlinks_count=0

http_package="`rpm -qa httpd`"

if [ "$http_package" != "" ]; then

	homeroot="`httpd -V 2>&1 | grep -v AH00558 | grep HTTPD_ROOT | awk -F= '{print $2}' | sed 's/["]//g'`"
	main_conffile="`httpd -V 2>&1 | grep -v AH00558 | egrep 'HTTPD_ROOT|SERVER_CONFIG_FILE' | awk -F= '{print $2}' | sed 's/["/]/ /g' | awk '{for(i=1;i<=NF;i++) {printf "/%s", $i}}'`"

	if [ -f $main_conffile ]; then

		include_option="`cat $main_conffile | egrep -v '[#]' | grep -i includeoptional | awk '{print $2}' | awk -F/ '{for(i=1;i<NF;i++) {printf "%s\n" , $i }}'`"
		include_dir="`awk -v home=$homeroot -v dir=$include_option 'BEGIN {printf "%s/%s", home , dir}'`"
		conf_find="`find $include_dir ! \( -name welcom* -o -name manual* -o -name autoindex* \) -name *.conf -type f -exec ls {} \;`"

		echo "- $main_conffile" >> $RESULT_COLLECT_FILE 2>&1
		echo "" >> $RESULT_COLLECT_FILE 2>&1
		main_symlinks="`cat $main_conffile | egrep -v '[#]|^$' | grep -i option | grep -i followsymlinks | sed 's/^ *//g'`"
		if [ "$main_symlinks" != "" ]; then
			dir_symlinks="`cat $main_conffile | egrep -v '[#]|^$' | grep -iv directoryindex | egrep -i 'directory|symlinks' | tail -30000`"
			echo "$dir_symlinks" >> $RESULT_COLLECT_FILE 2>&1
			symlinks_count=`expr $symlinks_count + 1`
			echo "" >> $RESULT_COLLECT_FILE 2>&1
		else
			echo "Not Found FollowSymlinks Configuration" >> $RESULT_COLLECT_FILE 2>&1
			echo "" >> $RESULT_COLLECT_FILE 2>&1
		fi
	else
		echo "Not Found Httpd Main Configuration File" >> $RESULT_COLLECT_FILE 2>&1
		echo "" >> $RESULT_COLLECT_FILE 2>&1
	fi

	
	if [ -d $include_dir ]; then
		if [ "$conf_find" != "" ]; then		
			for conf_file in $conf_find
			do
				echo "- $conf_file"  >> $RESULT_COLLECT_FILE 2>&1
				echo "" >> $RESULT_COLLECT_FILE 2>&1
				symlinks_conf="`cat $conf_file | egrep -v '[#]|^$' | grep -i option | grep -i followsymlinks | sed 's/^ *//g'`"
				if [ "$symlinks_conf" != "" ]; then
					dir_symlinks="`cat $conf_file | egrep -v '[#]|^$' | grep -iv directoryindex | egrep -i 'directory|symlinks' | tail -30000`"
					echo "$dir_symlinks" >> $RESULT_COLLECT_FILE 2>&1
					echo "" >> $RESULT_COLLECT_FILE 2>&1
					symlinks_count=`expr $symlinks_count + 1`
				else
					echo "Not Found FollowSymlinks Configuration" >> $RESULT_COLLECT_FILE 2>&1
					echo "" >> $RESULT_COLLECT_FILE 2>&1
				fi
			done
		else
			echo "Not Found Included Configuration File" >> $RESULT_COLLECT_FILE 2>&1
			echo "" >> $RESULT_COLLECT_FILE 2>&1
		fi
	else
		echo "Not Found Directory in the Including Conf Files" >> $RESULT_COLLECT_FILE 2>&1
		echo "" >> $RESULT_COLLECT_FILE 2>&1
	fi	

	if [ $symlinks_count -gt 0 ]; then
		echo "[ U-39 ] : 취약" >> $RESULT_VALUE_FILE 2>&1
	else
		echo "[ U-39 ] : 양호" >> $RESULT_VALUE_FILE 2>&1
	fi

else
	echo "Not Found Httpd Service" >> $RESULT_COLLECT_FILE 2>&1
	echo "" >> $RESULT_COLLECT_FILE 2>&1
	echo "[ U-39 ] : 검토(or 미설치)" >> $RESULT_VALUE_FILE 2>&1
fi
echo "====================== [U-39 Apache 링크 사용 금지 END]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
}

function u40() {
################################################################################################
#
# - 주요 정보 통신 기반 시설 | 서비스 관리
# - U-40 Apache 파일 업로드 및 다운로드 제한
#
################################################################################################
echo "[ U-40 ] : Check"
echo "====================== [U-40 Apache 파일 업로드 및 다운로드 제한 START]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1

http_package="`rpm -qa httpd`"

if [ "$http_package" != "" ]; then

        main_conffile="`httpd -V 2>&1 | grep -v AH00558 | egrep 'HTTPD_ROOT|SERVER_CONFIG_FILE' | awk -F= '{print $2}' | sed 's/["/]/ /g' | awk '{for(i=1;i<=NF;i++) {printf "/%s", $i}}'`"

        if [ -f $main_conffile ]; then
		limit_conf="`cat $main_conffile | egrep -v '[#]|^$' | grep -iv directoryindex | egrep -i 'limitrequestbody' | awk '{ for(i=1;i<=NF;i++) { if($i ~ /[0~9]/) {printf "%s\n", $i }}}'`"

                if [ "$limit_conf" != "" ]; then
			limit_find="`cat $main_conffile | egrep -v '[#]|^$' | grep -iv directoryindex | egrep -i 'limitrequestbody' | awk '{ for(i=1;i<=NF;i++) { if($i ~ /[0~9]/) { if($i>5000000) {printf "%s\n", $i }}}}'`"
			if [ "$limit_find" != "" ]; then
				dir_limit="`cat /etc/httpd/conf/httpd.conf | egrep -v '[#]|^$' | grep -iv directoryindex | egrep -i 'directory|limitrequestbody'`"
                        	echo "[ U-40 ] : 취약" >> $RESULT_VALUE_FILE 2>&1
                        	echo "$dir_limit" >> $RESULT_COLLECT_FILE 2>&1
			else
				dir_limit="`cat /etc/httpd/conf/httpd.conf | egrep -v '[#]|^$' | grep -iv directoryindex | egrep -i 'directory|limitrequestbody'`"
				echo "[ U-40 ] : 양호" >> $RESULT_VALUE_FILE 2>&1
				echo "$dir_limit" >> $RESULT_COLLECT_FILE 2>&1
			fi

                else
                       	echo "Not Found LimitRequestBody Configuration" >> $RESULT_COLLECT_FILE 2>&1
                        echo "[ U-40 ] : 양호" >> $RESULT_VALUE_FILE 2>&1
		fi
        else
                echo "Not Found Httpd Main Configuration File" >> $RESULT_COLLECT_FILE 2>&1
        fi

else
        echo "Not Found Httpd Service" >> $RESULT_COLLECT_FILE 2>&1
        echo "[ U-40 ] : 검토(or 미설치)" >> $RESULT_VALUE_FILE 2>&1
fi
echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "====================== [U-40 Apache 파일 업로드 및 다운로드 제한 END]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
}

function u41() {
################################################################################################
#
# - 주요 정보 통신 기반 시설 | 서비스 관리
# - U-41 Apache 웹서비스 영역의 분리
#
################################################################################################
echo "[ U-41 ] : Check"
echo "====================== [U-41 Apache 웹서비스 영역의 분리 START]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1

http_package="`rpm -qa httpd`"

if [ "$http_package" != "" ]; then

        main_conffile="`httpd -V 2>&1 | grep -v AH00558 | egrep 'HTTPD_ROOT|SERVER_CONFIG_FILE' | awk -F= '{print $2}' | sed 's/["/]/ /g' | awk '{for(i=1;i<=NF;i++) {printf "/%s", $i}}'`"

        if [ -f $main_conffile ]; then
                document_conf="`cat $main_conffile | egrep -v '[#]|^$' | grep -i documentroot | awk '{print $2}' | sed 's/^ *//g' | sed 's/["]//g'`"
                default_document="/var/www/html"

                if [ "$document_conf" != "" ]; then
			document_root="`cat $main_conffile | egrep -v '[#]|^$' | grep -i documentroot | sed 's/^ *//g' | sed 's/["]//g'`"			

                	if [ "$document_conf" = "$default_document" ]; then
                                echo "[ U-41 ] : 취약" >> $RESULT_VALUE_FILE 2>&1
                                echo "$document_root" >> $RESULT_COLLECT_FILE 2>&1
                        else
                                echo "[ U-41 ] : 양호" >> $RESULT_VALUE_FILE 2>&1
                                echo "$document_root" >> $RESULT_COLLECT_FILE 2>&1
                        fi
                else
                        echo "Not Found DocumentRoot Configuration" >> $RESULT_COLLECT_FILE 2>&1
                        echo "[ U-41 ] : 양호" >> $RESULT_VALUE_FILE 2>&1
                fi
        else
                echo "Not Found Httpd Main Configuration File" >> $RESULT_COLLECT_FILE 2>&1
        fi
else
        echo "Not Found Httpd Service" >> $RESULT_COLLECT_FILE 2>&1
        echo "[ U-41 ] : 검토(or 미설치)" >> $RESULT_VALUE_FILE 2>&1
fi
echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "====================== [U-41 Apache 웹서비스 영역의 분리 END]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
}

function u42() {
################################################################################################
#
# - 주요 정보 통신 기반 시설 | 패치 관리
# - U-42 최신 보안패치 및 벤더 권고사항 적용
#
################################################################################################

echo "[ U-42 ] : Check"
echo "====================== [U-42 최신 보안패치 및 벤더 권고사항 적용 START]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1

echo "[ U-42 ] : 검토" >> $RESULT_VALUE_FILE 2>&1
OS_KERNEL_VERSION=`uname -r`
echo "1. OS 커널 버전" >> $RESULT_COLLECT_FILE 2>&1
if [ "$OS_KERNEL_VERSION" != "" ]; then
	echo "- $OS_KERNEL_VERSION" >> $RESULT_COLLECT_FILE 2>&1
else
	echo "- Not Found OS Kernel Version" >> $RESULT_COLLECT_FILE 2>&1
fi

echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "2. OS 버전" >> $RESULT_COLLECT_FILE 2>&1
if [ -f "/etc/debian_version" -a -f "/etc/lsb-release" ]; then
	OS_VERSION=`cat /etc/lsb-release | grep "^DISTRIB_RELEASE" | cut -d '=' -f2`
	if [ "$OS_VERSION" != "" ]; then
		OS_FULL_VERSION="Ubuntu $OS_VERSION"
		echo "- $OS_FULL_VERSION" >> $RESULT_COLLECT_FILE 2>&1
	else
		echo "- Not Found OS Version" >> $RESULT_COLLECT_FILE 2>&1
	fi
elif [ -f "/etc/redhat-release" ]; then
	OS_FULL_VERSION=`cat /etc/redhat-release | grep "CentOS"`
	if [ "$OS_FULL_VERSION" != "" ]; then
		echo "- $OS_FULL_VERSION" >> $RESULT_COLLECT_FILE 2>&1
	else
		echo "- Not Found OS Version" >> $RESULT_COLLECT_FILE 2>&1
	fi
else
	echo "- Not Found OS Version" >> $RESULT_COLLECT_FILE 2>&1
fi

echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "====================== [U-42 최신 보안패치 및 벤더 권고사항 적용 END]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1
}

function u43() {
################################################################################################
#
# - 주요 정보 통신 기반 시설 | 로그 관리
# - U-43 로그의 정기적 검토 및 보고
#
################################################################################################

echo "[ U-43 ] : Check"
echo "====================== [U-43 로그의 정기적 검토 및 보고 START]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1

echo "Step 1) 정기적인 로그 검토 및 분석 주기 수립" >> $RESULT_COLLECT_FILE 2>&1
echo "1. utmp, wtmp, btmp 등의 로그를 확인하여 마지막 로그인 시간, 접속 IP, 실패한 이력 등을 확인하여 계정 탈취 공격 및 시스템 해킹 여보를 검토" >> $RESULT_COLLECT_FILE 2>&1
echo "2. sulog를 확인하여 허용된 계정 외에 su 명령어를 통해 권한 상승을 시도하였는지 검토" >> $RESULT_COLLECT_FILE 2>&1
echo "3. xferlog를 확인하여 비인가자의 ftp 접근 여부를 검토" >> $RESULT_COLLECT_FILE 2>&1
echo "Step 2) 로그 분석에 대한 결과 보고서 작성" >> $RESULT_COLLECT_FILE 2>&1
echo "Step 3) 로그 분석 결과보고서 보고 체계 수립" >> $RESULT_COLLECT_FILE 2>&1
echo "[ U-43 ] : 검토" >> $RESULT_VALUE_FILE 2>&1

echo "" >> $RESULT_COLLECT_FILE 2>&1
echo "====================== [U-43 로그의 정기적 검토 및 보고 END]" >> $RESULT_COLLECT_FILE 2>&1
echo "" >> $RESULT_COLLECT_FILE 2>&1

echo "" >> $RESULT_VALUE_FILE 2>&1
echo "======================= Linux Security Check Script End =======================" >> $RESULT_COLLECT_FILE 2>&1
echo "======================= Linux Security Check Script End =======================" >> $RESULT_VALUE_FILE 2>&1
echo "[End Script]"
echo ""
echo "===== Please Checking Log File ====="
echo ""
}

u01
u02
u03
u04
u05
u06
u07
u08
u09
u10
u11
u12
u13
u14
u15
u16
u17
u18
u19
u20
u21
u22
u23
u24
u25
u26
u27
u28
u29
u30
u31
u32
u33
u34
u35
u36
u37
u38
u39
u40
u41
u42
u43
