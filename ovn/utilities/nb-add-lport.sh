for i in `seq 0 $(($2-1))`; do 
  ovn-nbctl lport-add sw-$1 sw-$1-port$i
done
