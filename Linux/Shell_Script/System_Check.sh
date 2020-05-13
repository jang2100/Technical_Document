#!/bin/bash
#
#
Date=`date +%Y_%m_%d`
#
Result_Collect_Log=SysCheck_Collect_${Date}.log
Result_Value_log=SysCheck_Value_${Date}.log

#
#
function Network () {
echo -e "==================================================  Network Interface Card Infomation  =============================================\n"		>> ${Result_Collect_Log}
cat /etc/sysconfig/network-scripts/ifcfg-*                                                                       						>> ${Result_Collect_Log}
echo																				>> ${Result_Collect_Log}
echo -e "==================================================    Network Connection Infomation    =============================================\n"		>> ${Result_Collect_Log}
netstat -natpeu                                                                                         							>> ${Result_Collect_Log}
echo                                                                                               								>> ${Result_Collect_Log}
echo -e "================================================== Gateway Healthing Check Infomation ==============================================\n"		>> ${Result_Collect_Log}
ping -c 3 192.168.1.2                                                          											>> ${Result_Collect_Log}
   if [ `tail -2 ${Result_Collect_Log} | awk '{print $4}' | sed -n '1p'` = "3" ]; then
      echo -e "\n================================================= FTP Server Healthing Check Infomation ============================================\n"	>> ${Result_Collect_Log}
            ping -c 3 192.168.1.150                                                 >> ${Result_Collect_Log}
            if [ `tail -2 ${Result_Collect_Log} | awk '{print $4}' | sed -n '1p'` = "3" ]; then
               return 100
            else
               return 200
            fi
      else
            return 300
      fi
}

function Network2 () {
return_val=$?
if [ $return_val -eq 100 ]; then
   return_val="[Network]	양호"
elif [ $return_val -eq 200 ]; then
   return_val="[Network]	점검"
elif [ $return_val -eq 300 ]; then
   return_val="[Network]	점검"
fi

echo "${return_val}"					>> ${Result_Value_log}
}

function Memory () {
TM=`free -m | grep ^Mem | awk '{print $3}'`
FORTM=0
TSM=`free -m | grep ^Swap | awk '{print $3}'`
FORTSM=0
SWAP=`free -m | grep ^Swap | awk '{print $2}'`
MEM=`free -m | grep ^Mem | awk '{print $2}'`
MEM2=`echo "$MEM 4" | awk '{print $1 * $2}'`
SWAP2=`echo "$SWAP 4" | awk '{print $1 * $2}'`

for ((i=1;i<5;i++)); do
    	ADD=`expr $FORTM + $TM`
    	FORTM=$ADD
    	ADD2=`expr $FORTSM + $TSM`
    	FORTSM=$ADD2
done

actual=$((100*FORTM/MEM2))
swap=$((100*FORTSM/SWAP2))
echo "========================================================= Memory Infomation ========================================================" >> ${Result_Collect_Log}
echo "" >> ${Result_Collect_Log}
echo "Used   Swap Memory : ${swap}%" 			>> ${Result_Collect_Log}
echo "Used Actual Memory : ${actual}%" 			>> ${Result_Collect_Log}
echo "" >> ${Result_Collect_Log}

if [ $actual -ge 80 ] || [ $swap -ge 80 ]; then
    	echo "[Memory]	점검"				>> ${Result_Value_log}
else
    	echo "[Memory]	양호" 				>> ${Result_Value_log}
fi
}


function Disk () {

dis1=`df -h`
dis2=`df -h | sed -n '1p'`
dis3=`df -h | grep "[8-9][0-9][%]\|100%"`
users=`cat /etc/passwd | cut -d: -f1,3 | awk -F: '$2 > 999 {printf "%-10s\n", $1}' | grep -v nfsnobody`
A=`find /sdd1 /sdd2 /sdd3 /sdd4 /Logical_Group /var /home -user $name -type f -ls 2> /dev/null | awk '{ sum += $7 } END { printf "%.1fMB\n",sum / (1024*1024) }'`

echo -e "========================================================= Disk Information =========================================================\n"	>> ${Result_Collect_Log}
echo "$dis1"                     			>> ${Result_Collect_Log}
echo							>> ${Result_Collect_Log}


if [ "$dis3" != "" ]; then
echo -e "=========================================================== Disk 80% Over ==========================================================\n"	>> ${Result_Collect_Log}
echo "$dis2"						>> ${Result_Collect_Log}
echo "$dis3"						>> ${Result_Collect_Log}
echo                         				>> ${Result_Collect_Log}
echo "[Disk]		점검"				>> ${Result_Value_log}
else
echo "[Disk]		양호"				>> ${Result_Value_log}

fi
echo -e "============================================================= Users Disk ===========================================================\n"         >> ${Result_Collect_Log}
for name in $users
do
       printf "%-20s" $name				>> ${Result_Collect_Log}
       echo $A						>> ${Result_Collect_Log}
done
echo                        				>> ${Result_Collect_Log}

}


function Cpu () {
echo -e "============================================================= Cpu Usage  ===========================================================\n"        >> ${Result_Collect_Log}
sar -u | grep % | head -1 | sed 's/%//g' | awk '{printf "%s\t%13s\t%13s\t%13s\n" , $5, $6 ,$7 ,$10}' >> $Result_Collect_Log
sar -u 1 5 | sed -n '9p' | awk '{printf "%s%\t%12s%\t%12s%\t%12s%\n" , $3, $4, $5, $8}' >> $Result_Collect_Log


CORES=`grep cores /proc/cpuinfo | awk '{print $4}'`
LOAD=`top -b -n 1 | grep average | awk '{print $12}'`
IFCORES=`echo "$CORES 0.7" | awk '{printf "%.f", ($1 * $2) * 100}'`
IFLOAD=`echo "$LOAD 100" | awk '{printf "%.f", $1 * $2}'`

if [ $IFCORES -ge $IFLOAD ]; then
        echo "[CPU]		양호" 			>> $Result_Value_log
else
        echo "[CPU]		점검" 			>> $Result_Value_log
fi

echo 	 						>> $Result_Collect_Log
echo -e "============================================================= Cpu Average  =========================================================\n"        >> $Result_Collect_Log
uptime 							>> $Result_Collect_Log
echo 							>> $Result_Collect_Log
}


function Service() {
IFS=$'\n'
Service_Check=(`systemctl list-units --type service | egrep 'failed|running|exited' | sed s/●/""/g`)

service_count=0

echo -e "========================================================== Service Information =====================================================\n"      >> $Result_Collect_Log
for i in ${Service_Check[@]}
do
       if [ "`echo $i | awk '{print $2}'`" = "failed" ]; then
           tmp=`echo $i | awk '{ print $1 }'`
           printf "%-50s\tLoad\t Failed Service\n" $tmp 		>> $Result_Collect_Log
           service_count=`expr $sum + 1`

       fi
done
for i in ${Service_Check[@]}
do
       if [ "`echo $i | awk '{print $3}'`" = "failed" ]; then
           tmp=`echo $i | awk '{ print $1 }'`
           printf "%-50s\tActive\t Failed Service\n" $tmp        	>> $Result_Collect_Log
           service_count=`expr $sum + 1`
       fi
done
for i in ${Service_Check[@]}
do
       if [ "`echo $i | awk '{print $4}'`" = "failed" ]; then
           tmp=`echo $i | awk '{ print $1 }'`
           printf "%-50s\tSub\t Failed Service\n" $tmp        		>> $Result_Collect_Log
           service_count=`expr $sum + 1`
   fi
done
for i in ${Service_Check[@]}
do
       if [ "`echo $i | awk '{print $4}'`" = "exited" ]; then
           tmp=`echo $i | awk '{ print $1 }'`
           printf "%-50s\tSub\t Exited Service\n" $tmp        		>> $Result_Collect_Log
       fi
done

IFS=" "

if [ $service_count -gt 0 ]; then
        echo "[Service]	점검"                       		>>$Result_Value_log
else
        echo "[Service]	양호"                     		>>$Result_Value_log
fi
}


Network
Network2
Memory
Disk
Cpu
Service
