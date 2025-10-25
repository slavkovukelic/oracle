
#!/bin/bash
#
# SLaV - Mar-2024
# Program to optimize Oracle Linux 8.x for
# Oracle Databaseand Fusion middleware products
#
# Variables
#
HOSTNAME=`/bin/hostname`
SHORT_HOSTNAME=`echo $HOSTNAME | cut -d"." -f1`
export IP_ADDR=`/sbin/ifconfig | grep "inet addr" | grep -v "127.0.0.1" | awk '{ print $2 }' | cut -d":" -f2`
mkdir -p /INSTALL
mkdir -p /iso
export HERE=`pwd`
export OLTMP=/root/.oltmp
export INSTLOG=/tmp/install.log
export ISO_DIR=/iso
export INSTALL_DIR=/INSTALL
export ISO_FILE=""
unalias cp
#
#
# ...................
function f_intro()
# ...................
{
clear
tput civis
#
virtcent=$((`tput lines`/2))
horcent=$((`tput cols`/2-10))
tput setf 6
tput cup $virtcent $horcent && echo "${OracleProduct}"
sleep 1
clear
tput cup $virtcent $horcent && echo "Checking"
sleep 1
tput cup $virtcent $horcent && echo "                   "
sleep 1
tput cup $virtcent $horcent && echo "Checking"
sleep 1
tput cup $virtcent $horcent && echo "                   "
sleep 1
tput cup $virtcent $horcent && echo "Preparing.        "
sleep .1
tput cup $virtcent $horcent && echo "Preparing..       "
sleep .1
tput cup $virtcent $horcent && echo "Preparing...      "
sleep .1
tput cup $virtcent $horcent && echo "Preparing....     "
sleep .1
tput cup $virtcent $horcent && echo "Preparing.....    "
sleep .1
tput cup $virtcent $horcent && echo "Preparing......   "
sleep .1
tput cup $virtcent $horcent && echo "Preparing.......  "
sleep .1
tput cup $virtcent $horcent && echo "Preparing.......  "
sleep .1
tput cup $virtcent $horcent && echo "Preparing.......  "
sleep .1
tput cup $virtcent $horcent && echo "Preparing........ "
sleep .1
tput cup $virtcent $horcent && echo "Preparing........."
sleep 1
tput cup $virtcent $horcent && echo "    R E A D Y     "
sleep 1
clear
tput civis
tput cnorm
}
#
#
# ...................
function f_memo()
# ...................
{
umount /INSTALL        > /dev/null 2>&1
sleep 2
clear
export OL_RELEASE=`cat /etc/redhat-release`
echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
echo "$OL_RELEASE"
echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
echo "Your VM-template is Oracle-Products-11g/12c ready. "
echo "There is no need to run this script again!"
echo "Before you start clonning this VM, manually check:"
echo "IP Configuration:"
echo "    /etc/sysconfig/network"
echo "    /etc/sysconfig/network-scripts/ifcfg-eth0"
echo "    /etc/hosts"
echo "    /etc/resolv.conf"
echo "    /etc/ntp.conf"
echo "Remove ISO from /ISO directory or umount Virtual-CD"
echo "Install-Log: $INSTLOG "
echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
echo "Reboot your VM"
}
# ...................
function f_is_root()
# ...................
{
if [ "$UID" -ne 0 ]; then
    echo "This script requires root privileges to run properly."
  exit
fi
echo  > $INSTLOG       > /dev/null 2>&1
}
#
#
# ...................
function f_ol_release()
# ...................
{
  VERCHECK=`grep 8. /etc/redhat-release > /dev/null; echo $?`
    if [ "$VERCHECK" -eq "1" ]; then
      echo "Incorrect Operating System" 
      echo "This script only works for Oracle Enterprise Linux 8.x"
       exit 1
    fi
}
#
# ...................
function f_arch()
# ...................
{
ARCHITECTURE="`/bin/uname -m`"
if [ "$ARCHITECTURE" != "x86_64" ]; then
  echo "32 Bit Operating System Detected!" 
  echo "This script only works on 64-bit platforms!"
  exit 1
fi  
}
#
# ...................
function f_ip_check()
# ...................
{
cp /etc/hosts $OLTMP/etc_hosts.boba > /dev/null 2>&1
IPCHECK=`cat /etc/hosts | grep $IP_ADDR`
  if [ "$IPCHECK" ] ; then
   echo "... Hosts file configured OK"          | tee -a $INSTLOG;
  else
   echo "# Added for fresh Oracle Installation"    >>  /etc/hosts
   echo "$IP_ADDR   $HOSTNAME   $SHORT_HOSTNAME"   >>  /etc/hosts
   echo "#"                                        >>  /etc/hosts
   echo '... Hosts file configuration updated'  | tee -a $INSTLOG;
  fi
}
#
#
# ...................
f_start_again()
# ...................
{
cp $OLTMP/etc_sysconfig_selinux.boba       /etc/sysconfig/selinux        > /dev/null 2>&1
cp $OLTMP/etc_sysconfig_network.boba       /etc/sysconfig/network        > /dev/null 2>&1
cp $OLTMP/etc_pam.d_login.boba             /etc/pam.d/login              > /dev/null 2>&1
cp $OLTMP/etc_fstab.boba                   /etc/fstab                    > /dev/null 2>&1
cp $OLTMP/etc_security_limits.conf.boba    /etc/security/limits.conf     > /dev/null 2>&1
cp $OLTMP/etc_profile.boba                 /etc/profile                  > /dev/null 2>&1
cp $OLTMP/etc_security_limits.d_90-nproc.conf.boba /etc/security/limits.d/90-nproc.conf > /dev/null 2>&1
cp $OLTMP/etc_sysctl.conf.boba             /etc/sysctl.conf              > /dev/null 2>&1
cp $OLTMP/etc_hosts.boba                   /etc/hosts                    > /dev/null 2>&1
#
rm -rf /etc/oraInst.loc  > /dev/null 2>&1
rm -rf /etc/oratab       > /dev/null 2>&1
rm -rf /etc/init.d/wbl   > /dev/null 2>&1
rm -rf /etc/init.d/odb   > /dev/null 2>&1
rm -rf /root/utils       > /dev/null 2>&1
#
}
#
# ...................
f_modify_lx_files()
# ...................
{
cp /etc/sysconfig/selinux $OLTMP/etc_sysconfig_selinux.boba > /dev/null 2>&1
# Change SeLinux
sed -i  "s/SELINUX=enforcing/SELINUX=disabled/g"   /etc/sysconfig/selinux         > /dev/null 2>&1
sed -i  "s/SELINUX=permissive/SELINUX=disabled/g"  /etc/sysconfig/selinux         > /dev/null 2>&1
#
cp /etc/sysconfig/network $OLTMP/etc_sysconfig_network.boba > /dev/null 2>&1
echo "NETWORKING_IPV6=no"                      >> /etc/sysconfig/network
# echo "HOSTNAME=localhost.localdomain"        >> /etc/sysconfig/network
#
echo   "alias net-pf-10 off"     > /etc/modprobe.d/disable-ipv6.conf
echo   "options ipv6 disable=1"  >> /etc/modprobe.d/disable-ipv6.conf
echo   "install ipv6 /bin/true"  >> /etc/modprobe.d/disable-ipv6.conf
#
cp /etc/pam.d/login $OLTMP/etc_pam.d_login.boba > /dev/null 2>&1
echo "session    required     pam_limits.so" >>  /etc/pam.d/login
#
cp /etc/fstab $OLTMP/etc_fstab.boba > /dev/null 2>&1
echo "# /dev/xvdb1              /oradata                ext4    defaults,noatime             1 2" >> /etc/fstab
echo "# <NfsServer>:/<NfsExportDir> <LocalDir> nfs4 nointr,timeo=300,noatime"                     >> /etc/fstab
#
cp /etc/security/limits.conf $OLTMP/etc_security_limits.conf.boba > /dev/null 2>&1
#
cat >> /etc/security/limits.conf << EOF!
*  soft  core     unlimited
*  hard  core     unlimited
*  soft  memlock  150000000
*  hard  memlock  150000000
*  soft  stack    10240
*  hard  stack    32768
*  soft  nofile   131072
*  hard  nofile   131072
*  soft  nproc    131072
*  hard  nproc    131072
#
EOF!
cp  /etc/profile   $OLTMP/etc_profile.boba  > /dev/null 2>&1
echo "export PS1='\[\e[32m\]\u@\h \[\e[33m\]\w\[\e[0m\]\n\\$ '" >> /etc/profile
echo "#" >> /etc/profile
echo "if [ \$USER = "fmw" -o \$USER = "oracle"  ]; then"   >> /etc/profile
echo "  if [ \$SHELL = "/bin/ksh" ]; then"                   >> /etc/profile
echo "    ulimit -p 16384"                                  >> /etc/profile
echo "    ulimit -n 65536"                                  >> /etc/profile
echo "  else"                                               >> /etc/profile
echo "    ulimit -u 16384 -n 65536"                         >> /etc/profile
echo "  fi"                                                 >> /etc/profile
echo " umask 022"                                           >> /etc/profile
echo "fi "                                                  >> /etc/profile
echo "#"                                                    >> /etc/profile
echo "shopt -s dotglob"                                     >> /etc/profile
echo "PATH=\$PATH:."                                        >> /etc/profile
echo "export HISTTIMEFORMAT=\"%F %T \""                     >> /etc/profile
echo "#"                                                    >> /etc/profile
#
cp /etc/security/limits.d/90-nproc.conf $OLTMP/etc_security_limits.d_90-nproc.conf.boba > /dev/null 2>&1
sed -i  "s/1024/16384/g"   /etc/security/limits.d/90-nproc.conf         > /dev/null 2>&1
#
}
#
#
# ...................
f_sysctl_conf()
# ...................
{
cp  /etc/sysctl.conf $OLTMP/etc_sysctl.conf.boba > /dev/null 2>&1
#
cat >> /etc/sysctl.conf << EOF!
# BoBa - IPV4   
#
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.arp_notify = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.send_redirects = 0   
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.eth0.arp_announce=2
net.ipv4.conf.eth0.arp_ignore=1
net.ipv4.conf.eth0.rp_filter = 1
net.ipv4.conf.lo.arp_announce=2 
net.ipv4.conf.lo.arp_ignore=1
net.ipv4.conf.lo.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.inet_peer_gc_maxtime = 240
net.ipv4.inet_peer_gc_mintime = 80
net.ipv4.inet_peer_maxttl = 5
net.ipv4.inet_peer_minttl = 80
net.ipv4.inet_peer_threshold =65644
net.ipv4.ip_forward = 0
net.ipv4.ip_nonlocal_bind=1
net.ipv4.tcp_dsack = 0
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_time = 512
net.ipv4.tcp_low_latency = 1
net.ipv4.tcp_max_syn_backlog = 16384
net.ipv4.tcp_max_tw_buckets  = 2000000
net.ipv4.tcp_mem  = 1048576 16770216 1677721600
net.ipv4.tcp_rmem = 1048576 16777216 1677721600
net.ipv4.tcp_wmem = 1048576 16777216 1073741824
net.ipv4.udp_mem  = 1024000 8738000  1677721600
net.ipv4.tcp_sack = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_tw_recycle = 1
net.ipv4.tcp_tw_recycle = 10
net.ipv4.tcp_tw_reuse = 1                 
net.ipv4.ip_local_port_range = 1024 65500
#          
# BoBa KERNEL                     
#                      
kernel.shmmni = 4096        
kernel.shmall = 1073741824        
kernel.shmmax = 4398046511104
kernel.sem = 250 32000 100 128
kernel.msgmnb = 65535                  
kernel.msgmni = 2878               
kernel.msgmax = 65536   
kernel.core_uses_pid = 1
kernel.sysrq = 0
kernel.pid_max = 65536
#
# BoBa CORE
#
net.core.rmem_default = 8388608
net.core.rmem_max = 1073741824
net.core.wmem_default = 8388608
net.core.wmem_max = 1073741824
net.core.netdev_max_backlog  = 50000
net.core.somaxconn = 3000
#
# BoBa MISC
#
vm.overcommit_ratio = 17
kernel.core_pattern = /tmp
fs.aio-max-nr = 1048576
fs.file-max = 6815744
# vm.nr_hugepages = 77000
# BoBa Disable IPV6
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
#
EOF!
sysctl -p  > /dev/null 2>&1
#
}
#
#
# ...................
f_create_o_users()
# ...................
{
# First delete users (oracle and fmw)
userdel -rf oracle   > /dev/null 2>&1
userdel -rf fmw   > /dev/null 2>&1
rm -rf /oradata      > /dev/null 2>&1
groupdel oinstall    > /dev/null 2>&1
groupdel dba         > /dev/null 2>&1
#
echo "... Create Groups: oinstall,dba,nobody " | tee -a $INSTLOG
/usr/sbin/groupadd oinstall > /dev/null 2>&1
/usr/sbin/groupadd dba      > /dev/null 2>&1
/usr/sbin/groupadd nobody   > /dev/null 2>&1
echo "... Create Users: oracle,fmw " | tee -a $INSTLOG
/usr/sbin/useradd -u 203 -g dba -G oinstall,root  oracle  -d /oracle  -s /bin/bash  > /dev/null 2>&1
/usr/sbin/useradd -u 210 -g dba -G oinstall,root  fmw  -d /fmw  -s /bin/bash  > /dev/null 2>&1
#
echo "... Create directories for user oracle" | tee -a $INSTLOG
mkdir -p /oracle/base/dbhome
mkdir -p /oracle/INSTALL
mkdir -p /oracle/oraInventory
mkdir -p /oracle/ubin
mkdir -p /oracle/utils
mkdir -p /oracle/sys_sql
mkdir -p /oracle/tmp
mkdir -p /oradata
chown -R oracle:dba /oracle
chown -R oracle:dba /oradata
#
echo "... Create directories for user fmw" | tee -a $INSTLOG
mkdir -p /fmw/INSTALL
mkdir -p /fmw/mwlog
mkdir -p /fmw/ubin
mkdir -p /fmw/utils
mkdir -p /fmw/mwhome
mkdir -p /fmw/tmp
mkdir -p /fmw/oraInventory
chown -R fmw:dba /fmw
#
echo "... Passwd for oracle,fmw is manager1" | tee -a $INSTLOG
echo manager1 | passwd oracle --stdin > /dev/null 2>&1
echo manager1 | passwd fmw --stdin > /dev/null 2>&1
# 
echo "... System-Wide Files for oracle,fmw" | tee -a $INSTLOG
touch /etc/oraInst.loc
echo "inventory_loc=/oracle/oraInventory" > /etc/oraInst.loc
echo "inst_group=dba" >> /etc/oraInst.loc
touch /etc/oratab
chmod 777 /etc/oraInst.loc
chmod 777 /etc/oratab
#
touch /etc/init.d/wbl
touch /etc/init.d/odb
chmod 755 /etc/init.d/odb
chmod 755 /etc/init.d/wbl
chown oracle:dba /etc/init.d/odb
chown fmw:dba /etc/init.d/wbl
#
}
#
#
#
# ...................
function f_root_utils()
# ...................
{
echo "... Creating /root/utils"  | tee -a $INSTLOG
mkdir -p /root/utils > /dev/null 2>&1
#
echo "... /root/utils/additional_lx_utils.shl"  | tee -a $INSTLOG
cat >> /root/utils/hugepages_setting.shl << EOF
#!/bin/bash
#
# hugepages_setting.sh
#
# Linux bash script to compute values for the
# recommended HugePages/HugeTLB configuration
#
# Note: This script does calculation for all shared memory
# segments available when the script is run, no matter it
# is an Oracle RDBMS shared memory segment or not.
# Check for the kernel version
KERN=`uname -r | awk -F. '{ printf("%d.%d\n",$1,$2); }'`
# Find out the HugePage size
HPG_SZ=`grep Hugepagesize /proc/meminfo | awk {'print $2'}`
# Start from 1 pages to be on the safe side and guarantee 1 free HugePage
NUM_PG=1
# Cumulative number of pages required to handle the running shared memory segments
for SEG_BYTES in `ipcs -m | awk {'print $5'} | grep "[0-9][0-9]*"`
do
   MIN_PG=`echo "$SEG_BYTES/($HPG_SZ*1024)" | bc -q`
   if [ $MIN_PG -gt 0 ]; then
      NUM_PG=`echo "$NUM_PG+$MIN_PG+1" | bc -q`
   fi
done
# Finish with results
    echo "Recommended setting: vm.nr_hugepages = $NUM_PG"
# End
grep Huge /proc/meminfo

EOF
#

echo "... /root/utils/enable_nfs.shl"  | tee -a $INSTLOG
cat >> /root/utils/enable_nfs.shl << EOF
#!/bin/bash
chmod 755 /etc/init.d/netfs
chmod 755 /etc/init.d/nfs
chmod 755 /etc/init.d/nfslock
chmod 755 /etc/init.d/portmap
chmod 755 /etc/init.d/rpcgssd
chmod 755 /etc/init.d/rpcsvcgssd
chmod 755 /etc/init.d/rpcidmapd
chmod 755 /etc/init.d/rpcbind
chmod 755 /etc/init.d/rpcsvcgssd
chmod 755 /etc/init.d/cachefilesd
chkconfig --level 345 netfs             on
chkconfig --level 345 nfs               on
chkconfig --level 345 nfslock           on
chkconfig --level 345 portmap           on
chkconfig --level 345 rpcgssd           on
chkconfig --level 345 rpcsvcgssd        on
chkconfig --level 345 rpcbind           on
chkconfig --level 345 rpcidmapd         on
chkconfig --level 345 rpcsvcgssd        on
chkconfig --level 345 cachefilesd       on
EOF
#
echo "... /root/utils/disable_nfs.shl"  | tee -a $INSTLOG
cat >> /root/utils/disable_nfs.shl << EOF
#!/bin/bash
chkconfig  netfs             off
chkconfig  nfs               off
chkconfig  nfslock           off
chkconfig  portmap           off
chkconfig  rpcgssd           off
chkconfig  rpcsvcgssd        off
chkconfig  rpcidmapd         off
chkconfig  rpcsvcgssd        off
chkconfig  cachefilesd       off
chmod 444 /etc/init.d/netfs
chmod 444 /etc/init.d/nfs
chmod 444 /etc/init.d/nfslock
chmod 444 /etc/init.d/portmap
chmod 444 /etc/init.d/rpcgssd
chmod 444 /etc/init.d/rpcsvcgssd
chmod 444 /etc/init.d/rpcidmapd
chmod 444 /etc/init.d/rpcsvcgssd
chmod 444 /etc/init.d/cachefilesd
EOF
#
echo "... /root/utils/enable_ocfs_iscsi.shl"  | tee -a $INSTLOG
cat >> /root/utils/enable_ocfs_iscsi.shl << EOF

EOF
#
echo "... /root/utils/enable_ocfs_iscsi.shl"  | tee -a $INSTLOG
cat >> /root/utils/enable_ocfs_iscsi.shl << EOF
#!/bin/bash
chmod 755 /etc/init.d/o2cb
chmod 755 /etc/init.d/ocfs2
chmod 755 /etc/init.d/iscsi
chmod 755 /etc/init.d/iscsid
chkconfig oc2b    --level 345 on
chkconfig ocfs2   --level 345 on
chkconfig iscsid  --level 345 on
chkconfig iscsi   --level 345 on
service ocfs2 stop
service o2cb stop
service iscid start
service iscsi start
EOF
#

echo "... /root/utils/disable_ocfs_iscsi.shl"  | tee -a $INSTLOG
cat >> /root/utils/disable_ocfs_iscsi.shl << EOF
#!/bin/bash
service o2cb  stop
service ocfs2 stop
service iscid stop
service iscsi stop
chkconfig oc2b   off
chkconfig ocfs2  off
chkconfig iscsid off
chkconfig iscsi  off
chmod 444 /etc/init.d/o2cb
chmod 444 /etc/init.d/ocfs2
chmod 444 /etc/init.d/iscsid
chmod 444 /etc/init.d/iscsi
EOF
#

#
echo "... /root/utils/mem_calc.shl"  | tee -a $INSTLOG
cat >> /root/utils/mem_calc.shl << EOF
#!/bin/bash
# Output lines suitable for sysctl configuration based
# on total amount of RAM on the system.  The output
# will allow up to 50% of physical memory to be allocated
# into shared memory.
#
page_size=\`getconf PAGE_SIZE\`
phys_pages=\`getconf _PHYS_PAGES\`
#
if [ -z "\$page_size" ]; then
  echo Error:  cannot determine page size
  exit 1
fi
#
if [ -z "\$phys_pages" ]; then
  echo Error:  cannot determine number of memory pages
  exit 2
fi
#
shmall=\`expr \$phys_pages / 2\`
shmmax=\`expr \$shmall \* \$page_size\`
#
echo \# Maximum shared segment size in bytes
echo kernel.shmmax = \$shmmax
echo \# Maximum number of shared memory segments in pages
echo kernel.shmall = \$shmall
EOF
#
echo "... /root/utils/change_something.shl"  | tee -a $INSTLOG
cat >> /root/utils/change_something.shl << EOF
#!/bin/bash
find . -type f | xargs sed -i 's/STRING_BEFORE/STRING_AFTER/g'
EOF
#
echo "... /root/utils/mount_cifs_example.shl"  | tee -a $INSTLOG
cat >> /root/utils/mount_cifs_example.shl << EOF
mount -t cifs //<WinServer>/<DirName> -o username=<username>,password=<password> <LocalDirectory>
EOF
#
chmod 755 /root/utils/*.*
}
#
#
# ...................
function f_init_wbl()
# ...................
{
cat >> /etc/init.d/wbl << EOF!
#!/bin/bash
#
# Run-level Startup script for the WCC,WCP,SOA,OHS 11g 
# For single server installation or N1 of cluster
# BoBa - Aug-2013
#
# chkconfig: 2345 14 86
# description: Start-Stop Oracle-FMW-11g Components
#
### BEGIN INIT INFO
# Provides:          Oracle FMW Components
# Required-Start:    \$local_fs
# Required-Stop:     \$local_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Oracle FMW-Control
# Description:       Oracle FMW Components
#
ORA_OWNR="fmw"
WLOG_START=/fmw/mwlog/MwlStart.log
WLOG_STOP=/fmw/mwlog/MwlStop.log
touch \$WLOG_START
touch \$WLOG_STOP
/bin/chown fmw:dba \$WLOG_START
/bin/chown fmw:dba \$WLOG_STOP
# Remove old Logs 
find /fmw -type f -name *.log   -exec rm {} \;
find /fmw -type f -name *.out0* -exec rm {} \;
find /fmw -type f -name *.log0* -exec rm {} \;
#
        echo \$PATH                                                             > \$WLOG_START 2>&1
        echo "---------------------------------------------------------"       >> \$WLOG_START 2>&1
#
case "\$1" in
    start)
      #  ++++++++++++++++++++++++
      #  WebLogic and NodeManager
      # +++++++++++++++++++++++++
         echo "-------------------------WebLogic------------------------"     >> \$WLOG_START 2>&1
         su - \$ORA_OWNR --command="startWebLogic.sh"                          >> \$WLOG_START 2>&1 &
         sleep 60
         echo "OK Weblogic+"
        #
         echo "-------------------------NodeManager---------------------"     >> \$WLOG_START 2>&1
        su - \$ORA_OWNR --command="startNodeManager.sh"                        >> \$WLOG_START 2>&1 &
         sleep 10
         echo "OK NodeManager"
      # +++++++++++++++++++++++++
      # SOA
      # +++++++++++++++++++++++++
        #  echo "-----------------------soa_server1-----------------------"    >> \$WLOG_START 2>&1
        # su - \$ORA_OWNR --command="startManagedWebLogic.sh soa_server1"       >> \$WLOG_START 2>&1 &
        #  sleep 80
        #  echo "OK SOA"
        #
        #  echo "-----------------------bam_server1-----------------------"    >> \$WLOG_START 2>&1
        # su - \$ORA_OWNR --command="startManagedWebLogic.sh bam_server1"       >> \$WLOG_START 2>&1 &
        #  sleep 80
        #  echo "OK BAM"
      # +++++++++++++++++++++++++
      # WebContent
      # +++++++++++++++++++++++++
        #  echo "-----------------------IBR_server1-----------------------"    >> \$WLOG_START 2>&1
        # su - \$ORA_OWNR --command="startManagedWebLogic.sh IBR_server1"       >> \$WLOG_START 2>&1 &
        #  sleep 80
        #  echo "OK IBR"
        #
        #  echo "-------------------------UCM_server1---------------------"    >> \$WLOG_START 2>&1
        # su - \$ORA_OWNR --command="startManagedWebLogic.sh UCM_server1"       >> \$WLOG_START 2>&1 &
        #  sleep 50
        #  echo "OK UCM"
        #  
        #  echo "-----------------------capture_server1-------------------"    >> \$WLOG_START 2>&1
        # su - \$ORA_OWNR --command="startManagedWebLogic.sh capture_server1"   >> \$WLOG_START 2>&1 &
        #  sleep 60
        #  echo "OK Capture"
        #
        #  echo "-----------------------URM_server1-----------------------"    >> \$WLOG_START 2>&1
        # su - \$ORA_OWNR --command="startManagedWebLogic.sh URM_server1"       >> \$WLOG_START 2>&1 &
        #  sleep 80
        #  echo "OK URM"
        #
        #  echo "-----------------------IPM_server1-----------------------"    >> \$WLOG_START 2>&1
        # su - \$ORA_OWNR --command="startManagedWebLogic.sh IPM_server1"       >> \$WLOG_START 2>&1 &
        #  sleep 80
        #  echo "OK IPM"
        #
        #  echo "-----------------------SSXA_server1-----------------------"   >> \$WLOG_START 2>&1
        # su - \$ORA_OWNR --command="startManagedWebLogic.sh SSXA_server1"      >> \$WLOG_START 2>&1 &
        #  sleep 80
        #  echo "OK SSXA"
      # +++++++++++++++++++++++++
      # WebPortal
      # +++++++++++++++++++++++++
        #  echo "-------------------------WC_Collaboration-----------------"    >> \$WLOG_START 2>&1
        # su - \$ORA_OWNR --command="startManagedWebLogic.sh WC_Collaboration1"  >> \$WLOG_START 2>&1 &
        #  sleep 60
        #  echo "OK Colaboration"
        #
        #  echo "-------------------------WC_Portlet---------------------"      >> \$WLOG_START 2>&1
        # su - \$ORA_OWNR --command="startManagedWebLogic.sh WC_Portlet1"        >> \$WLOG_START 2>&1 &
        #  sleep 60
        #  echo "OK Portlet"
        #
        #  echo "-------------------------WC_Spaces---------------------"       >> \$WLOG_START 2>&1
        # su - \$ORA_OWNR --command="startManagedWebLogic.sh WC_Spaces1"         >> \$WLOG_START 2>&1 &
        #  sleep 60
        #  echo "OK Spaces"
        #
        #  echo "-------------------------WC_Utilities---------------------"    >> \$WLOG_START 2>&1
        # su - \$ORA_OWNR --command="startManagedWebLogic.sh WC_Utilities1"      >> \$WLOG_START 2>&1 &
        #  sleep 60
        #  echo "OK Utils"
      # +++++++++++++++++++++++++
      # OBIEE
      # +++++++++++++++++++++++++
        #  echo "-----------------------bi_server1------------------------"     >> \$WLOG_START 2>&1
        # su - \$ORA_OWNR --command="startManagedWebLogic.sh bi_server1"         >> \$WLOG_START 2>&1 &
        #  sleep 100
        #  echo "OK OBI"
        # echo "-----------------------opmnctl---------------------------"      >> \$WLOG_START 2>&1
        # su - \$ORA_OWNR --command="opmnctl startall"                           >> \$WLOG_START 2>&1 &
      # +++++++++++++++++++++++++
      # ODI
      # +++++++++++++++++++++++++
        echo "-----------------------Agents  -----------------------------"     >> \$WLOG_START 2>&1
        # su - \$ORA_OWNR --command="agent_oracleDIAgent.sh"                     >> \$WLOG_START 2>&1 &
        # sleep 10
        # echo "OK AGENTS"
        # echo "-----------------------odi_server1------------------------"     >> \$WLOG_START 2>&1
        # su - \$ORA_OWNR --command="startManagedWebLogic.sh odi_server1"        >> \$WLOG_START 2>&1 &
        # sleep 10
      # +++++++++++++++++++++++++
      # OHS
      # +++++++++++++++++++++++++
        #  echo "-------------------------OHS---------------------"             >> \$WLOG_START 2>&1
        # su - \$ORA_OWNR --command="opmnctl startall"                           >> \$WLOG_START 2>&1 &
        #  sleep 10
        #  su - \$ORA_OWNR --command="opmnctl status"                            >> \$WLOG_START 2>&1 &
        #  sleep 10
        #  echo "OK OHS"
        #
        ;;
    stop)
      # +++++++++++++++++++++++++
      # WebPortal
      # +++++++++++++++++++++++++
        #  echo "------------------------- WC_Collaboration ----------------"   > \$WLOG_STOP 2>&1
        # su - \$ORA_OWNR --command="stopManagedWebLogic.sh WC_Collaboration1"  >> \$WLOG_STOP 2>&1 &
	#  echo "WC_Collaboration"
        #  echo "------------------------- WC_Portlet ---------------------"   >> \$WLOG_STOP 2>&1
	# su - \$ORA_OWNR --command="stopManagedWebLogic.sh WC_Portlet1"        >> \$WLOG_STOP 2>&1 &
	#  echo "WC_Portlet"
        #  echo "------------------------- WC_Spaces ----------------------"   >> \$WLOG_STOP 2>&1
	# su - \$ORA_OWNR --command="stopManagedWebLogic.sh WC_Spaces1"         >> \$WLOG_STOP 2>&1 &
	#  echo "WC_Spaces"
        #  echo "------------------------- WC_Utilities -------------------"   >> \$WLOG_STOP 2>&1
    	# su - \$ORA_OWNR --command="stopManagedWebLogic.sh WC_Utilities1"      >> \$WLOG_STOP 2>&1 &
	#  echo "WC_Utilities"
      # +++++++++++++++++++++++++
      # WebContent
      # +++++++++++++++++++++++++
        #  echo "------------------------- capture_server1 ----------------"   >> \$WLOG_STOP 2>&1
        # su - \$ORA_OWNR --command="stopManagedWebLogic.sh capture_server1"    >> \$WLOG_STOP 2>&1 &
	#  echo "capture_server1"
        #  echo "------------------------- SSXA_server1 -------------------"   >> \$WLOG_STOP 2>&1
	# su - \$ORA_OWNR --command="stopManagedWebLogic.sh SSXA_server1"       >> \$WLOG_STOP 2>&1 &
	#  echo "SSXA_server1"
        #  echo "-------------------------IBR_server1----------------------"   >> \$WLOG_STOP 2>&1
        # su - \$ORA_OWNR --command="stopManagedWebLogic.sh IBR_server1"        >> \$WLOG_STOP 2>&1
        #  echo "IBR_server1"
        # echo "-------------------------IPM_server1-----------------------"   >> \$WLOG_STOP 2>&1
        # su - \$ORA_OWNR --command="stopManagedWebLogic.sh IPM_server1"        >> \$WLOG_STOP 2>&1
        #  echo "IPM_server1"
        #  echo "-------------------------URM_server1----------------------"   >> \$WLOG_STOP 2>&1
        # su - \$ORA_OWNR --command="stopManagedWebLogic.sh URM_server1"        >> \$WLOG_STOP 2>&1
        #  echo "URM_server1"
        #  echo "-------------------------UCM_server1----------------------"   >> \$WLOG_STOP 2>&1
        # su - \$ORA_OWNR --command="stopManagedWebLogic.sh UCM_server1"        >> \$WLOG_STOP 2>&1
        #  echo "UCM_server1"
      # +++++++++++++++++++++++++
      # SOA
      # +++++++++++++++++++++++++
        #  echo "------------------------- soa_server1 --------------------"   >> \$WLOG_STOP 2>&1
	# su - \$ORA_OWNR --command="stopManagedWebLogic.sh soa_server1"        >> \$WLOG_STOP 2>&1 &
	#  echo "soa_server1"
        #  echo "------------------------- bam_server1 --------------------"   >> \$WLOG_STOP 2>&1
	# su - \$ORA_OWNR --command="stopManagedWebLogic.sh bam_server1"        >> \$WLOG_STOP 2>&1 &
	#  echo "bam_server1"
      # +++++++++++++++++++++++++
      # ODI
      # +++++++++++++++++++++++++
        # echo "-------------------------odi_server1----------------------"    >> \$WLOG_STOP 2>&1
        # echo -n "Shutdown ODI Server: "                                      >> \$WLOG_STOP 2>&1
        # su - \$ORA_OWNR --command="stopManagedWebLogic.sh odi_server1"        >> \$WLOG_STOP 2>&1
      # +++++++++++++++++++++++++
      # OBIEE
      # +++++++++++++++++++++++++   
        # echo "-------------------------opmnctl-------------------------"      >> \$WLOG_STOP 2>&1
        # su - \$ORA_OWNR --command="opmnctl stopall"                            >> \$WLOG_STOP 2>&1
        # echo "-------------------------bi_server1----------------------"      >> \$WLOG_STOP 2>&1
        # echo -n "Shutdown BiServer: "                                         >> \$WLOG_STOP 2>&1
        # su - \$ORA_OWNR --command="stopManagedWebLogic.sh bi_server1"          >> \$WLOG_STOP 2>&1    
      # +++++++++++++++++++++++++
      # WebLogic and NodeManager
      # +++++++++++++++++++++++++
         echo "-------------------StopWeblogic--------------------------"       >> \$WLOG_STOP 2>&1
        su - \$ORA_OWNR --command="stopWebLogic.sh"                              >> \$WLOG_STOP 2>&1
         echo "WebLogic"
        kill -9 \`ps -ef | grep NodeManager | grep nodemanager | cut -c10-15\`   
         echo "NodeManager"
      # +++++++++++++++++++++++++
      # OHS
      # +++++++++++++++++++++++++
        #  echo "-------------------------OHS_server---------------------"      >> \$WLOG_STOP 2>&1
        # su - \$ORA_OWNR --command="opmnctl stopall"                            >> \$WLOG_STOP 2>&1
        #  echo "OHS"
        ;;
    reload|restart)
        \$0 stop
        \$0 start
        ;;
    *)
        echo "Usage: \$0 start|stop|restart|reload"
esac
exit 0
EOF!
#
chmod 755 /etc/init.d/wbl
}
#
#
# ...................
function f_init_odb()
# ...................
{
cat >> /etc/init.d/odb << EOF!
#!/bin/bash
#
# Run-level Startup script for the OracleDB-11g
# BoBa - Aug-2013
#
# chkconfig: 2345 14 86
# description: Start-Stop OracleDB-11g
#
### BEGIN INIT INFO
# Provides:          OracleDatabase 11g
# Required-Start:    \$local_fs
# Required-Stop:     \$local_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Oracle DB-Control
# Description:       Oracle Database Listener and Services
#
TMP="/oracle/tmp"
ORA_HOME="/oracle/base/dbhome"
ORA_OWNR="oracle"
#
# if the executables do not exist -- display error
if [ ! -f \$ORA_HOME/bin/dbstart -o ! -d \$ORA_HOME ]
then
        echo "Oracle startup: cannot start"
        exit 1
fi
#
# depending on parameter -- startup, shutdown, restart
# of the instance and listener or usage display
#
case "\$1" in
    start)
        # Oracle listener and instance startup
        echo -n "Starting Oracle: "
        su - \$ORA_OWNR --command="\$ORA_HOME/bin/dbstart \$ORA_HOME"
        sleep 15
        su - \$ORA_OWNR --command="\$ORA_HOME/bin/emctl start dbconsole"
        echo "OracleDatabase Started"
        ;;
    stop)
        # Oracle listener and instance shutdown
        echo -n "Shutdown Oracle: "
        su - \$ORA_OWNR --command="\$ORA_HOME/bin/emctl stop dbconsole"
        sleep 10
        su - \$ORA_OWNR --command="\$ORA_HOME/bin/dbshut \$ORA_HOME"
        sleep 10
        rm -rf \$TMP/*
        echo "OracleDatabase Stopped"
        ;;
    reload|restart)
        \$0 stop
        \$0 start
        ;;
    *)
        echo "Usage: \$0 start|stop|restart|reload"
        exit 1
esac
exit 0
EOF!
#
chmod 755 /etc/init.d/odb
}
#
#
# ...................
function f_utils_oracle()
# ...................
{
cat >> /oracle/.bash_profile << EOF!
export TMP=/oracle/tmp                    
export TMPDIR=\$TMP                             
export ORACLE_BASE=/oracle/base                    
export ORACLE_HOME=\$ORACLE_BASE/dbhome 
# Replace <DB_NAME> with your DB-SID        
# export ORACLE_SID=<DB_NAME>
export ORACLE_TERM=xterm                    
export PATH=/usr/sbin:\$PATH                
export PATH=\$ORACLE_HOME/bin:\$PATH            
export PATH=\$PATH:\$HOME/ubin                 
export NLS_LANG=AMERICAN_AMERICA.UTF8       
export JAVA_HOME=/usr/share/java
export ORA_NLS10=\$ORACLE_HOME/nls/data
export THREADS_FLAG=native
export PATH=\$JAVA_HOME:\$PATH
export ORACLE_PATH=/oracle/sys_sql
export CV_ASSUME_DISTID=OEL7.6
#
export LD_LIBRARY_PATH=\$ORACLE_HOME/lib
export LD_LIBRARY_PATH=\${LD_LIBRARY_PATH}:\$ORACLE_HOME/oracm/lib
export LD_LIBRARY_PATH=\${LD_LIBRARY_PATH}:/lib:/usr/lib:/usr/local/lib
export LIBPATH=\$LD_LIBRARY_PATH
#
export CLASSPATH=\$ORACLE_HOME/JRE
export CLASSPATH=\${CLASSPATH}:\$ORACLE_HOME/jlib
export CLASSPATH=\${CLASSPATH}:\$ORACLE_HOME/rdbms/jlib
export CLASSPATH=\${CLASSPATH}:\$ORACLE_HOME/network/jlib
#
umask 022
cd \$HOME/tmp
# Remove this comment once you set DB-SID
clear
echo " "
echo "........................................................................"
echo " Set your Database-Sid in /oracle/.bash_profile"
echo " And remove this comment"
echo "........................................................................"
EOF!
chown oracle:dba /oracle/.bash_profile
#
cat >> /oracle/utils/listener.ora << EOF!
SID_LIST_LISTENER =
  (SID_LIST =
    (SID_DESC =
      (GLOBAL_DBNAME = <DB_NAME>)
      (ORACLE_HOME = /oracle/base/dbhome)
      (SID_NAME = <DB_NAME>)
    )
  )
#
LISTENER =
  (DESCRIPTION_LIST =
   (SDU=16384)
   (TDU=16384)
    (DESCRIPTION =
      (ADDRESS = (PROTOCOL = TCP)(HOST = <HOST_NAME>)(PORT = 1521))
    )
    (DESCRIPTION =
      (ADDRESS = (PROTOCOL = IPC)(KEY = EXTPROC1521))
    )
  )
#
ADR_BASE_LISTENER = /oracle/base
EOF!
chown oracle:dba /oracle/utils/listener.ora
#
cat >> /oracle/utils/shrept.lst << EOF!
# function entry points for genclntsh.sh
network : snaumihi_inithostinfo
network : snaumbg_gmt
network : naedpwd_encrypt
network : naumbsb_bld_singlebyte
network : ztapis
network : nlgh
EOF!
chown oracle:dba /oracle/utils/shrept.lst
#
cat >> /oracle/utils/sqlnet.ora << EOF!
NAMES.DIRECTORY_PATH= (TNSNAMES, EZCONNECT)
ADR_BASE = /oracle/base
EOF!
chown oracle:dba /oracle/utils/sqlnet.ora
#
cat >> /oracle/utils/tnsnames.ora << EOF!
<DB_NAME> =
  (DESCRIPTION =
    (SDU=16384)
    (TDU=16384)
    (ADDRESS = (PROTOCOL = TCP)(HOST = <HOST_NAME>)(PORT = 1521))
    (CONNECT_DATA =
      (SERVER = DEDICATED)
      (SERVICE_NAME = <DB_NAME>)
    )
  )
EOF!
chown oracle:dba /oracle/utils/tnsnames.ora
#
}
#
#
# ...................
function f_utils_fmw()
# ...................
{
cat >> /fmw/utils/soa_ohs_wcc_wcp_dot_bash_profile.txt << EOF!
# BoBa - Install Variables
export I_OHS_NAME=OHS
export I_OHS_INSTANCE=instance1
export I_OHS_CMP_NAME=ohs1
#
export I_SOA_NAME=SOA
export I_ECM_NAME=ECM
export I_WCP_NAME=WCP
#
export IATEMPDIR=/fmw/tmp
export TEMP=/fmw/tmp
export TMP=/fmw/tmp
export TMPDIR=/fmw/tmp
export TEMPDIR=/fmw/tmp
# User specific environment and startup programs
export JAVA_HOME=/jrockit-jdk
export MW_HOME=/fmw/mwhome
export WEBLOGIC_HOME=/fmw/mwhome/wlserver_10.3
# export ORACLE_HOME=/fmw/mwhome/WCP
export INSTANCE_HOME=/fmw/mwhome/OHS/instances/\$I_OHS_INSTANCE
export OHS_HOME=/fmw/mwhome/\$I_OHS_NAME
export ECM_HOME=/fmw/mwhome/\$I_ECM_NAME
export SOA_HOME=/fmw/mwhome/\$I_SOA_NAME
export SOA_ORACLE_HOME=/fmw/mwhome/SOA
export WCP_HOME=/fmw/mwhome/\$I_WCP_NAME
export WLS_HOME=\$WEBLOGIC_HOME
export PATH=\$JAVA_HOME/bin:\$PATH:/fmw/ubin
#
export PATH=\$PATH:/fmw/mwhome/user_projects/domains/fmw_dom/bin
export PATH=\$PATH:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin:/bin
export PATH=\$PATH:\$HOME/ubin
export PATH=\$PATH:/fmw/ubin
export PATH=\$ORACLE_HOME/bin:\$PATH
export PATH=\$INSTANCE_HOME/bin:\$PATH
export PATH=\$WLS_HOME/server/bin:\$PATH:/fmw/mwhome/oracle_common/common/bin
export PATH=\$WCP_HOME/bin:\$ECM_HOME/bin:\$OHS_HOME/bin:\$SOA_HOME/bin:\$PATH
#
cd /fmw/tmp
alias servers='cd /fmw/mwhome/user_projects/domains/fmw_dom/servers'
# export WLS_REDIRECT_LOG=/fmw/mwlog/WebLogic.log
EOF!
chown fmw:dba /fmw/utils/soa_ohs_wcc_wcp_dot_bash_profile.txt
#
cat >> /fmw/utils/obiee_bash_profile.txt << EOF!
export JAVA_HOME=/fmw/mwhome/Oracle_BI1/jdk
export MW_HOME=/fmw/mwhome
export WEBLOGIC_HOME=/fmw/mwhome/wlserver_10.3
export WLS_HOME=\$WEBLOGIC_HOME
export ORACLE_HOME=/fmw/mwhome/Oracle_BI1
export INSTANCE_HOME=/fmw/mwhome/instances/OBI1
export DOMAIN_NAME=fmw_dom
export DOMAIN_HOME=/fmw/mwhome/user_projects/domains/fmw_dom
export OBIEE_HOME=/fmw/mwhome/Oracle_BI1
#
export PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin:/bin:.
export PATH=\$MW_HOME/server/bin:\$PATH
export PATH=\$MW_HOME/user_projects/domains/fmw_dom/bin:\$PATH
export PATH=\$WEBLOGIC_HOME/bin:\$WEBLOGIC_HOME/server/bin:\$PATH
export PATH=\$DOMAIN_HOME/bin:\$PATH
export PATH=\$ORACLE_HOME/bin:\$PATH
export PATH=\$INSTANCE_HOME/bin:\$PATH
export PATH=\$JAVA_HOME/bin:\$PATH:/fmw/mwhome/Oracle_BI1/bifoundation/server/bin
export PATH=\$PATH:/fmw/mwhome/oracle_common/common/bin
cd /fmw/mwlog
#
alias rpd='cd /fmw/mwhome/instances/OBI1/bifoundation/OracleBIServerComponent/coreapplication_obis1/repository; ls; pwd'
EOF!
chown fmw:dba /fmw/utils/obiee_bash_profile.txt
#
cat >> /fmw/utils/odi_bash_profile.txt << EOF!
export JAVA_HOME=/fmw/java
export MW_HOME=/fmw/mwhome
export WEBLOGIC_HOME=/fmw/mwhome/wlserver_10.3
export ORACLE_HOME=/fmw/mwhome/ODI
export ODI_HOME=\$ORACLE_HOME
export DOMAIN_NAME=fmw_dom
export DOMAIN_HOME=/fmw/mwhome/user_projects/domains/fmw_dom
export ORACLE_COMMON=/fmw/mwhome/oracle_common/common/bin
export ODI_AGENT_BIN=/fmw/mwhome/ODI/oracledi/agent/bin
#
export PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
export PATH=/fmw/mwhome/ODI/oracledi/client/odi/bin:\$PATH
export PATH=\$JAVA_HOME/bin:\$PATH
export PATH=\$ODI_AGENT_BIN:\$PATH
export PATH=\$ORACLE_COMMON:\$PATH
export PATH=\$WEBLOGIC_HOME/server/bin:\$PATH
export PATH=\$ODI_HOME/bin:\$PATH
export PATH=\$DOMAIN_HOME/bin:\$PATH
export PATH=.:\$HOME/ubin:\$PATH
# Oracle DB Stuff
# export ORACLE_BASE=/oracle/base
# export ORACLE_HOME=\$ORACLE_BASE/dbhome
# export ORACLE_TERM=xterm
# export PATH=\$PATH:\$ORACLE_HOME/bin
# export NLS_LANG=AMERICAN_AMERICA.UTF8
# export LD_LIBRARY_PATH=\${LD_LIBRARY_PATH}:\$ORACLE_HOME/lib
EOF!
chown fmw:dba /fmw/utils/odi_bash_profile.txt
#
cat >> /fmw/utils/nodemanager.properties << EOF!
LogFile=/fmw/mwlog/nodemanager.log
DomainsFile=/fmw/mwhome/wlserver_10.3/common/nodemanager/nodemanager.domains
StartScriptEnabled=true
PropertiesVersion=10.3
LogLimit=0
DomainsDirRemoteSharingEnabled=true
AuthenticationEnabled=true
NodeManagerHome=/fmw/mwhome/wlserver_10.3/common/nodemanager
JavaHome=/jrockit-jdk
LogLevel=INFO
DomainsFileEnabled=true
StartScriptName=startWebLogic.sh
ListenAddress=
NativeVersionEnabled=true
ListenPort=5556
LogToStderr=true
SecureListener=false
LogCount=1
DomainRegistrationEnabled=false
StopScriptEnabled=false
QuitEnabled=true
LogAppend=true
StateCheckInterval=100
CrashRecoveryEnabled=true
LogFormatter=weblogic.nodemanager.server.LogFormatter
ListenBacklog=50
AutoRestart=true
EOF!
chown fmw:dba /fmw/utils/nodemanager.properties
#
cat >> /fmw/.bash_profile << EOF!
tput clear
echo " "
echo " "
ls -lpsa /fmw/utils
echo " "
echo " "
echo "........................................................................"
echo " In directory /fmw/utils you have environment files for: "
echo " SOA_WCC_WCP_OHS = soa_ohs_wcc_wcp_dot_bash_profile.txt"
echo " OBIEE           = obiee_bash_profile.txt"
echo " ODI             = odi_bash_profile.txt"
echo "........................................................................"
echo " Replace your /fmw/.bash_profile with sutiable environment"
echo " ForExample: If you are planning to use OBIEE then"
echo " cp /fmw/utils/odi_bash_profile.txt /fmw/.bash_profile"
echo " Logout/Login and your environment will be set"
EOF!
chown fmw:dba /fmw/.bash_profile
#
#
cat >> /root/utils/monitoring_tools.shl << EOF!
service psacct start
export NMON=mndc
monitorix
iftop
htop
iotop
iostat
ac -d
ac -p
nethogs
arpwatch
nmon
collectl
iptraf
mtr -c 10 --report localhost
EOF!
chmod 755 /root/utils/monitoring_tools.shl
#
#
}
#
# ...................
function f_init_iso()
# ...................
{
mkdir -p $ISO_DIR      > /dev/null 2>&1
mkdir -p $INSTALL_DIR  > /dev/null 2>&1
mkdir -p $OLTMP        > /dev/null 2>&1
chmod 755 $INSTALL_DIR > /dev/null 2>&1
umount /INSTALL        > /dev/null 2>&1
# Citrix CDROM
mount -t iso9660 -o ro /dev/cdrom $INSTALL_DIR > /dev/null 2>&1
# VMware CDROM
# mount -t iso9660 -o ro /dev/dvd1 $INSTALL_DIR  > /dev/null 2>&1
# ISO Mount
# Check if ISO directory is empty
if [ ! "$(ls -A $ISO_DIR)" ]; then
     ISO_FILE=`ls /ISO/*.iso`             > /dev/null 2>&1
     mount -o loop $ISO_FILE $INSTALL_DIR > /dev/null 2>&1
fi 

# Check if INSTALL directory is empty
if [ "$(ls -A $INSTALL_DIR)" ]; then
    echo "... ISO Mounted on $INSTALL_DIR"  | tee -a $INSTLOG
else
    tput clear
    echo " ================================================================"
    echo " INSTALL mount is empty, to install linux packages:"
    echo " Place OracleLinux-ISO image in  Virtual-DVD-Drive"
    echo "   or"
    echo " Place OracleLinux-ISO image in /ISO folder on this VM"
    echo " ================================================================"
    exit 1
fi
}
#
# ...................
function f_ora_packs()
# ...................
{
echo "... Installing required packages" 
#
# dnf clean headers
dnf clean metadata
dnf clean all
rm -rf /var/cache/dnf
mkdir /etc/yum.repos.d/LOCKED
mv /etc/yum.repos.d/*.* /etc/yum.repos.d/LOCKED
#
echo "... Mount-Local-Repo from ISO" 
cat >> /etc/yum.repos.d/local.repo << EOF
[lcAppStream]
name=local DVD
baseurl=file:///INSTALL/AppStream
enabled=1
gpgcheck=0

[lcBaseOS]
name=local DVD
baseurl=file:///INSTALL/BaseOS
enabled=1
gpgcheck=0
EOF
#
#
# Now List Repositories
#
echo "======================================"
echo "Repositories:"
sed -n -e "/^\[/h; /priority *=/{ G; s/\n/ /; s/ity=/ity = /; p }" /etc/yum.repos.d/*.repo | sort -k3n
echo "======================================"
echo ""
sleep 3
dnf -y install yum*
#
# Packages from Oracle Repo
#

# dnf -y groupinstall "Server with GUI"
dnf -y group install "GNOME"
dnf -y install automake*
dnf -y install binutils-*  
dnf -y install compat-libcap*
dnf -y install compat-libstdc++*  
dnf -y install compat-libstdc++*i686
dnf -y install compat-libstdc++-33*
dnf -y install elfutils-devel*
dnf -y install elfutils-libelf*
dnf -y install firefox
dnf -y install gcc*
dnf -y install gd
dnf -y install ghostscript*i686
dnf -y install glibc*
dnf -y install glibc*.i686
dnf -y install kernel-devel
dnf -y install kernel-headers
dnf -y install ksh*
dnf -y install libaio*
dnf -y install libgcc*
dnf -y install libstdc*
dnf -y install libX*
dnf -y install libX*i686*
dnf -y install libX11*i686*
dnf -y install make* 
dnf -y install mlocate*
dnf -y install numactl-devel-*
dnf -y install nfs*
dnf -y install ntp*
dnf -y install ocfs*
dnf -y install openmotif*
dnf -y install openmotif.i686 
dnf -y install openldap-clients*
dnf -y install perl
dnf -y install python
dnf -y install slocate*
dnf -y install sysstat*
dnf -y install sharutils
dnf -y install telnet
dnf -y install tigervnc-server
dnf -y install tree
dnf -y install samba
dnf -y install unixODBC*
dnf -y install zlib* 
dnf -y install zlib*.i686
dnf -y install xterm
dnf -y remove python-krbV-*
dnf -y install python*
dnf -y install qt*
dnf -y install PyQt4
dnf -y install wget
dnf -y install unzip*
dnf -y install ORBit2-devel 
dnf -y install libnsl*
dnf install -y bc    
dnf install -y binutils
dnf install -y compat-libcap1
dnf install -y compat-libstdc++-33
dnf install -y dtrace-modules
dnf install -y dtrace-modules-headers
dnf install -y dtrace-modules-provider-headers
dnf install -y dtrace-utils
dnf install -y elfutils-libelf
dnf install -y elfutils-libelf-devel
dnf install -y fontconfig-devel
dnf install -y glibc
dnf install -y glibc-devel
dnf install -y ksh
dnf install -y libaio
dnf install -y libaio-devel
#dnf install -y libdtrace-ctf-devel
dnf install -y libXrender
dnf install -y libXrender-devel
dnf install -y libX11
dnf install -y libXau
dnf install -y libXi
dnf install -y libXtst
dnf install -y libgcc
dnf install -y librdmacm-devel
dnf install -y libstdc++
dnf install -y libstdc++-devel
dnf install -y libxcb
dnf install -y make
dnf install -y net-tools # Clusterware
dnf install -y nfs-utils # ACFS
dnf install -y python # ACFS
dnf install -y python-configshell # ACFS
dnf install -y python-rtslib # ACFS
dnf install -y python-six # ACFS
dnf install -y targetcli # ACFS
dnf install -y smartmontools
dnf install -y sysstat
dnf install -y unixODBC
# New for OL8
dnf install -y libnsl
dnf install -y libnsl.i686
dnf install -y libnsl2
dnf install -y libnsl2.i686
dnf -y install xfsprogs xfsdump
dnf -y install e4defrag e2fsprogs
package-cleanup -y --oldkernels --count=3
package-cleanup -y --oldkernels --count=2
package-cleanup -y --oldkernels --count=1
#
cd /etc/yum.repos.d
wget https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm 
rpm -ivh epel-release-latest-8.noarch.rpm
#
#
dnf -y install libpcap libpcap-devel ncurses ncurses-devel
dnf -y install iptraf
dnf -y install monitorix
dnf -y install iotop
dnf -y install iostat
dnf -y install iftop
dnf -y install htop
dnf -y install iotop
dnf -y install psacct
dnf -y install nethogs
dnf -y install arpwatch
dnf -y install nmon
dnf -y install collectl
dnf -y install mtr
dnf -y install sysstat
# dnf -y install keepalived
dnf -y install socat
#
cd $HERE
#
#
}
#
#
# ...................
function unw_services()
# ...................
{
echo "========================================"
echo " Turning off unecessary services        "
echo "========================================"
sleep 5
echo "disabling grdisc" 
sleep 0.2
chkconfig grdisc off                 2>/dev/null
echo "disabling gnmb" 
sleep 0.2
chkconfig gnmb off                 2>/dev/null
echo "disabling gcgconfig" 
sleep 0.2
chkconfig gcgconfig off                 2>/dev/null
echo "disabling go2cb" 
sleep 0.2
chkconfig go2cb off                 2>/dev/null
echo "disabling gabrt-oops" 
sleep 0.2
chkconfig gabrt-oops off                 2>/dev/null
echo "disabling giscsid" 
sleep 0.2
chkconfig giscsid off                 2>/dev/null
echo "disabling gntpd" 
sleep 0.2
chkconfig gntpd off                 2>/dev/null
echo "disabling gxinetd" 
sleep 0.2
chkconfig gxinetd off                 2>/dev/null
echo "disabling gip6tables" 
sleep 0.2
chkconfig gip6tables off                 2>/dev/null
echo "disabling gautofs" 
sleep 0.2
chkconfig gautofs off                 2>/dev/null
echo "disabling gfirstboot" 
sleep 0.2
chkconfig gfirstboot off                 2>/dev/null
echo "disabling keepalived" 
sleep 0.2
chkconfig keepalived off                 2>/dev/null
echo "disabling gsssd" 
sleep 0.2
chkconfig gsssd off                 2>/dev/null
echo "disabling grestorecond" 
sleep 0.2
chkconfig grestorecond off                 2>/dev/null
echo "disabling glibvirt-guests" 
sleep 0.2
chkconfig glibvirt-guests off                 2>/dev/null
echo "disabling gwebmin" 
sleep 0.2
chkconfig gwebmin off                 2>/dev/null
echo "disabling gocfs2" 
sleep 0.2
chkconfig gocfs2 off                 2>/dev/null
echo "disabling gNetworkManager" 
sleep 0.2
chkconfig gNetworkManager off                 2>/dev/null
echo "disabling gmessagebus" 
sleep 0.2
chkconfig gmessagebus off                 2>/dev/null
echo "disabling grpcbind" 
sleep 0.2
chkconfig grpcbind off                 2>/dev/null
echo "disabling gkdump" 
sleep 0.2
chkconfig gkdump off                 2>/dev/null
echo "disabling gpostfix" 
sleep 0.2
chkconfig gpostfix off                 2>/dev/null
echo "disabling gbluetooth" 
sleep 0.2
chkconfig gbluetooth off                 2>/dev/null
echo "disabling ghaldaemon" 
sleep 0.2
chkconfig ghaldaemon off                 2>/dev/null
echo "disabling gnetconsole" 
sleep 0.2
chkconfig gnetconsole off                 2>/dev/null
echo "disabling gfunctions" 
sleep 0.2
chkconfig gfunctions off                 2>/dev/null
echo "disabling gcertmonger" 
sleep 0.2
chkconfig gcertmonger off                 2>/dev/null
echo "disabling gyum-cron" 
sleep 0.2
chkconfig gyum-cron off                 2>/dev/null
echo "disabling grpcidmapd" 
sleep 0.2
chkconfig grpcidmapd off                 2>/dev/null
echo "disabling grpcgssd" 
sleep 0.2
chkconfig grpcgssd off                 2>/dev/null
echo "disabling gdnsmasq" 
sleep 0.2
chkconfig gdnsmasq off                 2>/dev/null
echo "disabling girqbalance" 
sleep 0.2
chkconfig girqbalance off                 2>/dev/null
echo "disabling gmdmonitor" 
sleep 0.2
chkconfig gmdmonitor off                 2>/dev/null
echo "disabling gportreserve" 
sleep 0.2
chkconfig gportreserve off                 2>/dev/null
echo "disabling gabrtd" 
sleep 0.2
chkconfig gabrtd off                 2>/dev/null
echo "disabling gwpa_supplicant" 
sleep 0.2
chkconfig gwpa_supplicant off                 2>/dev/null
echo "disabling gcups" 
sleep 0.2
chkconfig gcups off                 2>/dev/null
echo "disabling gatd" 
sleep 0.2
chkconfig gatd off                 2>/dev/null
echo "disabling gsmartd" 
sleep 0.2
chkconfig gsmartd off                 2>/dev/null
echo "disabling gcgred" 
sleep 0.2
chkconfig gcgred off                 2>/dev/null
echo "disabling gnfs" 
sleep 0.2
chkconfig gnfs off                 2>/dev/null
echo "disabling grhnsd" 
sleep 0.2
chkconfig grhnsd off                 2>/dev/null
echo "disabling gnscd" 
sleep 0.2
chkconfig gnscd off                 2>/dev/null
echo "disabling gyum-updateonboot" 
sleep 0.2
chkconfig gyum-updateonboot off                 2>/dev/null
echo "disabling godb" 
sleep 0.2
chkconfig godb off                 2>/dev/null
echo "disabling gsmb" 
sleep 0.2
chkconfig gsmb off                 2>/dev/null
echo "disabling giptables" 
sleep 0.2
chkconfig giptables off                 2>/dev/null
echo "disabling gsandbox" 
sleep 0.2
chkconfig gsandbox off                 2>/dev/null
echo "disabling gpsacct" 
sleep 0.2
chkconfig gpsacct off                 2>/dev/null
echo "disabling gnfslock" 
sleep 0.2
chkconfig gnfslock off                 2>/dev/null
echo "disabling gsaslauthd" 
sleep 0.2
chkconfig gsaslauthd off                 2>/dev/null
echo "disabling gmcelogd" 
sleep 0.2
chkconfig gmcelogd off                 2>/dev/null
echo "disabling gavahi-daemon" 
sleep 0.2
chkconfig gavahi-daemon off                 2>/dev/null
echo "disabling gipsec" 
sleep 0.2
chkconfig gipsec off                 2>/dev/null
echo "disabling grpcsvcgssd" 
sleep 0.2
chkconfig grpcsvcgssd off                 2>/dev/null
echo "disabling gwinbind" 
sleep 0.2
chkconfig gwinbind off                 2>/dev/null
echo "disabling gypbind" 
sleep 0.2
chkconfig gypbind off                 2>/dev/null
echo "disabling giscsi" 
sleep 0.2
chkconfig giscsi off                 2>/dev/null
echo "disabling grsyslog" 
sleep 0.2
chkconfig grsyslog off                 2>/dev/null
echo "disabling gquota_nld" 
sleep 0.2
chkconfig gquota_nld off                 2>/dev/null
echo "disabling gabrt-ccpp" 
sleep 0.2
chkconfig gabrt-ccpp off                 2>/dev/null
echo "disabling gacpid" 
sleep 0.2
chkconfig gacpid off                 2>/dev/null
echo "disabling gvncserver" 
sleep 0.2
chkconfig gvncserver off                 2>/dev/null
echo "disabling gcpuspeed" 
sleep 0.2
chkconfig gcpuspeed off                 2>/dev/null
echo "disabling gauditd" 
sleep 0.2
chkconfig gauditd off                 2>/dev/null
echo "disabling gnetfs" 
sleep 0.2
chkconfig gnetfs off                 2>/dev/null
echo "disabling monitorix" 
sleep 0.2
chkconfig monitorix off                 2>/dev/null
# Disable Firewall
echo "disable firewall"
systemctl stop firewalld
systemctl disable firewalld

#
#
}
#
#
# ...................
function set_yum_repos()
# ...................
{
#
cp /etc/yum.repos.d/LOCKED/*.* /etc/yum.repos.d
mv /etc/yum.repos.d/local.repo /etc/yum.repos.d/LOCKED
#
# Now List Repositoryes
#
sleep 1
echo "======================================"
echo "Repositories:"
sed -n -e "/^\[/h; /priority *=/{ G; s/\n/ /; s/ity=/ity = /; p }" /etc/yum.repos.d/*.repo | sort -k3n
echo "======================================"
echo ""
sleep 2
yum-config-manager --disable local
#
UEK_KERNEL=`uname -a | grep uek`
# if [ -z "$UEK_KERNEL" ]; then
#   echo "This VM is Non-UEK Kernel"
#   yum-config-manager --enable   ol8_latest
#   yum-config-manager --disable  ol8_UEK_latest
# else
#   echo "This VM is UEK Kernel"
#   yum-config-manager --enable   ol8_UEK_latest
#   yum-config-manager --disable  ol8_latest
# fi
#
sleep 2
}
#
#
# ...................
function f_vnc()
# ...................
{
clear
echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
echo " Configure linux to start in non-graphical mode"
systemctl set-default multi-user.target
echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
echo " Configure VNC"
echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
echo "Add to: /etc/tigervnc/vncserver.users"
echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
echo ":1=oracle" >> /etc/tigervnc/vncserver.users
echo "#:1=fmw" >> /etc/tigervnc/vncserver.users
echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
mkdir -p /oracle/.vnc
echo "session=gnome"         > /oracle/.vnc/config
echo "geometry=1280x1024"   >> /oracle/.vnc/config 
echo "alwaysshared"         >> /oracle/.vnc/config 
chown -R oracle:dba /oracle/.vnc
#
mkdir -p /fmw/.vnc
echo "session=gnome"         > /fmw/.vnc/config
echo "geometry=1280x1024"   >> /fmw/.vnc/config 
echo "alwaysshared"         >> /fmw/.vnc/config
chown -R fmw:dba /fmw/.vnc
#
cat >> /etc/systemd/system/vncserver@\:1.service << EOF
[Unit]
Description=Remote desktop service (VNC)
After=syslog.target network.target

[Service]
Type=forking
User=oracle
Group=dba
WorkingDirectory=/oracle
ExecStartPre=/bin/sh -c '/usr/bin/vncserver -kill %i > /dev/null 2>&1 || :'
ExecStart=/usr/bin/vncserver %i -geometry 1280x1024
PIDFile=/oracle/.vnc/%H%i.pid
ExecStop=/bin/sh -c '/usr/bin/vncserver -kill %i > /dev/null 2>&1 || :'

[Install]
WantedBy=multi-user.target

EOF


systemctl daemon-reload
#
echo "systemctl start vncserver@:1.service" > /root/start_vnc.shl
chmod 755 /root/start_vnc.shl
echo "Log as oracle+fmw and run vncpasswd"
echo " then as root run systemctl start vncserver@:1.service or run /root/start_vnc.shl"
}

# ...................
function f_grubby()
# ...................
{
clear
echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
echo " Configure GRUB2 and Disable Transparent HugePages"
echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
echo "SERVICES: systemctl list-units --type service"
systemctl list-units --type service
export GRUBDFLTKERNEL=`grubby --default-kernel`
grubby --args="transparent_hugepage=never" --update-kernel $GRUBDFLTKERNEL
grubby --info $GRUBDFLTKERNEL
systemctl disable iscsi-shutdown.service
systemctl disable iscsi-shutdown
systemctl stop iscsi-shutdown
systemctl disable iscsid.service
systemctl stop iscsid.service
systemctl stop iscsid
systemctl disable iscsid
systemctl disable ModemManager.service
systemctl stop ModemManager.service
systemctl enable --now cockpit.socket
dnf remove -y --oldinstallonly --setopt installonly_limit=2 kernel
# dnf clean metadata
# dnf clean all
# rm -rf /var/cache/dnf/*
# mv -f /etc/yum.repos.d/*.* /etc/yum.repos.d/LOCKED
# ext4 defrag = https://www.baeldung.com/linux/ext4-filesystem-defragment
}
# ...................

# ...................
#
#
# Main
#
clear
echo "-----------------------------------------------------------"
echo "                  Run as root !"
echo " This program will run around 30+ minutes. "
echo " At the end your OL8 system will be optimized for: "
echo " 1) Database installation as oracle user "
echo " 2) Fusion-Middleware as fmw user"
echo " Initial password for oracle and fmw users is manager1"
echo " Install-Log is: $INSTLOG"
echo " "
echo "                    ! W A R N I N G !"
echo "      ! Existing oracle and fmw users will be removed !"
echo "                    ! W A R N I N G !"
echo " "
echo "-----------------------------------------------------------"
echo " Please press y to continue or n to abort    "
echo "-----------------------------------------------------------"
echo " "
while true; do
    read -p "CONTINUE y/n: " yn
    case $yn in
        [Yy]* ) 
          #
          f_is_root;
             echo "... Checking mandatory requirements"                 | tee -a $INSTLOG;
          f_ol_release;
          f_arch;        
          f_start_again;
              echo "... Optimizing configuration"                       | tee -a $INSTLOG;
          f_ip_check;
          f_modify_lx_files;
          f_sysctl_conf;
          f_create_o_users;
          f_root_utils;
          f_init_wbl;
          f_init_odb;
          f_utils_oracle;
          f_utils_fmw;
             echo "... Mounting OL install media"                       | tee -a $INSTLOG;
          f_init_iso;          
             echo "... Install packages from local media"               | tee -a $INSTLOG; 
          f_ora_packs                                                   | tee -a $INSTLOG;
          unw_services                                                  | tee -a $INSTLOG;
          set_yum_repos                                                 | tee -a $INSTLOG;
		  f_vnc                                                         | tee -a $INSTLOG;
		  f_grubby                                                      | tee -a $INSTLOG;
          f_intro;  
          f_memo;
             break;;
        [Nn]* ) exit;;
        * ) echo "Please answer yes or no.";;
    esac
done

]0;root@ppodb:~[32mroot@ppodb [33m~[0m
# 