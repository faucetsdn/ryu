for i in $(seq 1 7);
    do
    let port=i+6660
    xterm -title "app$i" -hold -e ryu-manager ryu/openexchange/network/shortest_route --ofp-tcp-listen-port=$port --oxp-role=domain --oxp-domain-id=$i --oxp-server-ip=10.103.23.29 --oxp-server-port=6688 --observe-links &
    done


