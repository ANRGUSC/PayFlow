
import os

os.system('sudo ovs-vsctl -- set Port s1-eth1 qos=@newqos -- --id=@newqos create QoS type=linux-htb other-config:max-rate=1000000000 queues=0=@q0,1=@q1,2=@q2,3=@q3,4=@q4,5=@q5,6=@q6 -- --id=@q0 create Queue other-config:min-rate=250000000 other-config:max-rate=250000000 -- --id=@q1 create Queue other-config:min-rate=250000000 other-config:max-rate=250000000 -- --id=@q2 create Queue other-config:min-rate=150000000 other-config:max-rate=150000000 -- --id=@q3 create Queue other-config:min-rate=150000000 other-config:max-rate=150000000 -- --id=@q4 create Queue other-config:min-rate=100000000 other-config:max-rate=100000000 -- --id=@q5 create Queue other-config:min-rate=100000000 other-config:max-rate=100000000 -- --id=@q6 create Queue other-config:min-rate=50000000 other-config:max-rate=50000000')
os.system('sudo ovs-vsctl -- set Port s1-eth2 qos=@newqos -- --id=@newqos create QoS type=linux-htb other-config:max-rate=1000000000 queues=7=@q0,8=@q1,9=@q2,10=@q3,11=@q4,12=@q5,13=@q6 -- --id=@q0 create Queue other-config:min-rate=250000000 other-config:max-rate=250000000 -- --id=@q1 create Queue other-config:min-rate=250000000 other-config:max-rate=250000000 -- --id=@q2 create Queue other-config:min-rate=150000000 other-config:max-rate=150000000 -- --id=@q3 create Queue other-config:min-rate=150000000 other-config:max-rate=150000000 -- --id=@q4 create Queue other-config:min-rate=100000000 other-config:max-rate=100000000 -- --id=@q5 create Queue other-config:min-rate=100000000 other-config:max-rate=100000000 -- --id=@q6 create Queue other-config:min-rate=50000000 other-config:max-rate=50000000')
os.system('sudo ovs-vsctl -- set Port s1-eth3 qos=@newqos -- --id=@newqos create QoS type=linux-htb other-config:max-rate=1000000000 queues=14=@q0,15=@q1,16=@q2,17=@q3,18=@q4,19=@q5,20=@q6 -- --id=@q0 create Queue other-config:min-rate=250000000 other-config:max-rate=250000000 -- --id=@q1 create Queue other-config:min-rate=250000000 other-config:max-rate=250000000 -- --id=@q2 create Queue other-config:min-rate=150000000 other-config:max-rate=150000000 -- --id=@q3 create Queue other-config:min-rate=150000000 other-config:max-rate=150000000 -- --id=@q4 create Queue other-config:min-rate=100000000 other-config:max-rate=100000000 -- --id=@q5 create Queue other-config:min-rate=100000000 other-config:max-rate=100000000 -- --id=@q6 create Queue other-config:min-rate=50000000 other-config:max-rate=50000000')
os.system('sudo ovs-vsctl -- set Port s1-eth4 qos=@newqos -- --id=@newqos create QoS type=linux-htb other-config:max-rate=1000000000 queues=21=@q0,22=@q1,23=@q2,24=@q3,25=@q4,26=@q5,27=@q6 -- --id=@q0 create Queue other-config:min-rate=250000000 other-config:max-rate=250000000 -- --id=@q1 create Queue other-config:min-rate=250000000 other-config:max-rate=250000000 -- --id=@q2 create Queue other-config:min-rate=150000000 other-config:max-rate=150000000 -- --id=@q3 create Queue other-config:min-rate=150000000 other-config:max-rate=150000000 -- --id=@q4 create Queue other-config:min-rate=100000000 other-config:max-rate=100000000 -- --id=@q5 create Queue other-config:min-rate=100000000 other-config:max-rate=100000000  -- --id=@q6 create Queue other-config:min-rate=50000000 other-config:max-rate=50000000')


os.system('sudo ovs-vsctl -- set Port s2-eth1 qos=@newqos -- --id=@newqos create QoS type=linux-htb other-config:max-rate=1000000000 queues=0=@q0,1=@q1,2=@q2,3=@q3,4=@q4,5=@q5,6=@q6 -- --id=@q0 create Queue other-config:min-rate=250000000 other-config:max-rate=250000000 -- --id=@q1 create Queue other-config:min-rate=250000000 other-config:max-rate=250000000 -- --id=@q2 create Queue other-config:min-rate=150000000 other-config:max-rate=150000000 -- --id=@q3 create Queue other-config:min-rate=150000000 other-config:max-rate=150000000 -- --id=@q4 create Queue other-config:min-rate=100000000 other-config:max-rate=100000000 -- --id=@q5 create Queue other-config:min-rate=100000000 other-config:max-rate=100000000 -- --id=@q6 create Queue other-config:min-rate=50000000 other-config:max-rate=50000000')
os.system('sudo ovs-vsctl -- set Port s2-eth2 qos=@newqos -- --id=@newqos create QoS type=linux-htb other-config:max-rate=1000000000 queues=7=@q0,8=@q1,9=@q2,10=@q3,11=@q4,12=@q5,13=@q6 -- --id=@q0 create Queue other-config:min-rate=250000000 other-config:max-rate=250000000 -- --id=@q1 create Queue other-config:min-rate=250000000 other-config:max-rate=250000000 -- --id=@q2 create Queue other-config:min-rate=150000000 other-config:max-rate=150000000 -- --id=@q3 create Queue other-config:min-rate=150000000 other-config:max-rate=150000000 -- --id=@q4 create Queue other-config:min-rate=100000000 other-config:max-rate=100000000 -- --id=@q5 create Queue other-config:min-rate=100000000 other-config:max-rate=100000000 -- --id=@q6 create Queue other-config:min-rate=50000000 other-config:max-rate=50000000')
	
os.system('sudo ovs-vsctl -- set Port s3-eth1 qos=@newqos -- --id=@newqos create QoS type=linux-htb other-config:max-rate=1000000000 queues=0=@q0,1=@q1,2=@q2,3=@q3,4=@q4,5=@q5,6=@q6 -- --id=@q0 create Queue other-config:min-rate=250000000 other-config:max-rate=250000000 -- --id=@q1 create Queue other-config:min-rate=250000000 other-config:max-rate=250000000 -- --id=@q2 create Queue other-config:min-rate=150000000 other-config:max-rate=150000000 -- --id=@q3 create Queue other-config:min-rate=150000000 other-config:max-rate=150000000 -- --id=@q4 create Queue other-config:min-rate=100000000 other-config:max-rate=100000000 -- --id=@q5 create Queue other-config:min-rate=100000000 other-config:max-rate=100000000 -- --id=@q6 create Queue other-config:min-rate=50000000 other-config:max-rate=50000000')
os.system('sudo ovs-vsctl -- set Port s3-eth2 qos=@newqos -- --id=@newqos create QoS type=linux-htb other-config:max-rate=1000000000 queues=7=@q0,8=@q1,9=@q2,10=@q3,11=@q4,12=@q5,13=@q6 -- --id=@q0 create Queue other-config:min-rate=250000000 other-config:max-rate=250000000 -- --id=@q1 create Queue other-config:min-rate=250000000 other-config:max-rate=250000000 -- --id=@q2 create Queue other-config:min-rate=150000000 other-config:max-rate=150000000 -- --id=@q3 create Queue other-config:min-rate=150000000 other-config:max-rate=150000000 -- --id=@q4 create Queue other-config:min-rate=100000000 other-config:max-rate=100000000 -- --id=@q5 create Queue other-config:min-rate=100000000 other-config:max-rate=100000000 -- --id=@q6 create Queue other-config:min-rate=50000000 other-config:max-rate=50000000')