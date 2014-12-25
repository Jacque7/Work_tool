@echo off
set snort=D:\snort
if "%1"=="" goto mymsg
goto start%1

:start-s
snort  -i 2 -A console -c %snort%/etc/snort.conf -k none -l %snort%/log
goto end

:start-flist
if %2=="" goto mymsg
snort -A console -c %snort%/etc/snort.conf -k none -l %snort%/log --pcap-show --pcap-file %2 
goto end

:start-r
if %2=="" goto mymsg
snort -A console -c %snort%/etc/snort.conf -k none -l %snort%/log -r %2 --pcap-show
goto end

:start-list
if %2=="" goto mymsg
snort -A console -c %snort%/etc/snort.conf -k none -l %snort%/log --pcap-show -pcap-list %2 
goto end

:start-help
echo ssnort -s		start snort for stand for IDS
echo ssnort -flist filename	start snort with file what have pcap file list
echo ssnort -r pcapfile	start snort with pcap file
echo ssnort -list "list"	start snort with list what space separate list string,like this "a.pcap b.pcap"
goto end

:start-etc
notepad++ %snort%/etc/snort.conf
goto end

:start-edit
notepad++ %snort%/ssnort.bat
goto end

:mymsg
echo Input parameter is error,again!
:end