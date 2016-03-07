for i in `seq 0 $(($1-1))`; do
    ovn-nbctl lswitch-add sw-$i
done
