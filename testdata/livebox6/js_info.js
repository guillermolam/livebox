
var manufacturer='ARLT';
var isp='Jazztel';
var wan_mac_addr='f4:ca:e7:3d:72:9b';
var wan_mode='GPON';
var defroute_wan_ip="95.20.132.77";
var ipv6_info_buf="/";
var system={"cpuLoad":"5%", "total_mem":"398 MB", "free_mem":"140 MB", "total_flash":"0", "free_flash":"0"};
var main_notify='0';
addCfg("4g_mode", "983291000000", "Unavailable");
var ipv6_wan_ip="0:0:0:0:0:0:0:0";
(function(){
var wan_ipv6_info=ipv6_info_buf.split("/");
if(ipv6_info_buf==""||wan_ipv6_info[0]==""||wan_ipv6_info[0]=="::"){
ipv6_wan_ip="0:0:0:0:0:0:0:0";}
else{
ipv6_wan_ip=wan_ipv6_info[0].toUpperCase();}})();