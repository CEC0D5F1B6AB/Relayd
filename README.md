# Relayd

use raw socket achieve ipv4 nat（only tcp udp icmp proto）

it can use in protal auth network， when A host login the protal network

the other host can be inject the A host access the internet

program usage in openwrt
  program -l br-lan -w wan
  
  
br-lan is your lan network

wan is the protal network
