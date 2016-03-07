nb-add-lswitch.sh 5
nb-add-lport.sh 0 200
ovn-nbctl lswitch-del sw-0
ovs-appctl -t ovsdb-server memory/debug
