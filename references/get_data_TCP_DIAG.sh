#!/bin/bash

#insert the tcp_diag module
modprobe tcp_diag
#enable the tcp log tracing
cd /sys/kernel/debug/tracing
echo 1 > events/tcp/tcp_probe/enable
cd -   # get back to the previous folder

#disable tcp metric saving
sysctl net.ipv4.tcp_no_metrics_save=0
#enable/disable SACK
sysctl net.ipv4.tcp_sack=1

#set link properties - note that you first have to ADD the netem qdisc before CHANGE it
#change your params
tc qdisc change dev eth0 root netem loss 0.3% delay 200ms

# reset the log file so that we don't get past values
echo > /sys/kernel/debug/tracing/trace

#run your test
cc=reno    #check your parameter
iperf3 -c bigdatadb.polito.it -C cc

#now extract data
# NOTE: you need to filter the proper TCP connection
# TBD: may be it's possible to automatize this by parsing iperf3 output?
src_port=53012

	# get time
	cat /sys/kernel/debug/tracing/trace |grep cwnd| grep $src_port| tr -s ' '| cut -d ' ' -f 5|cut -d':' -f 1 >time
	#get data len
	cat /sys/kernel/debug/tracing/trace |grep cwnd| grep $src_port|cut -d '=' -f6|cut -d ' ' -f 1 >len
	#get SeqNo
	cat /sys/kernel/debug/tracing/trace |grep cwnd| grep $src_port|cut -d '=' -f7|cut -d ' ' -f 1 >seqno
	#get ack
	cat /sys/kernel/debug/tracing/trace |grep cwnd| grep $src_port|cut -d '=' -f8|cut -d ' ' -f 1 >una
	#get CWND
	cat /sys/kernel/debug/tracing/trace |grep cwnd| grep $src_port|cut -d '=' -f9|cut -d ' ' -f 1 >cwnd
	#get ssthresh
	cat /sys/kernel/debug/tracing/trace |grep cwnd| grep $src_port|cut -d '=' -f10|cut -d ' ' -f 1 >ssthresh
	#get snd_wnd
	cat /sys/kernel/debug/tracing/trace |grep cwnd| grep $src_port|cut -d '=' -f11|cut -d ' ' -f 1 >snd_wnd
	#get rtt
	cat /sys/kernel/debug/tracing/trace |grep cwnd| grep $src_port|cut -d '=' -f12|cut -d ' ' -f 1 >rtt
	
#put everything together	
paste time len seqno una cwnd ssthresh snd_wnd rtt> data


#now just quick&dirt plot it - TBD: better prepare a plot.gnu
gnuplot << EOF
	
	set term png
	set xlabel "time"
	
	#TBD: set proper labels
	set out "len_$cc.png"
	plot 'data' using 1:2

	set out "SeqNo_$cc.png"
	plot 'data' using 1:3

	set out "una_$cc.png"
	plot 'data' using 1:4

	set out "cwnd_$cc.png"
	plot 'data' using 1:5

	set out "ssthresh_$cc.png"
	plot 'data' using 1:6

	set out "snd_wnd_$cc.png"
	plot 'data' using 1:7

	set out "rtt_$cc.png"
	plot 'data' using 1:8


EOF
