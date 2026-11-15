var wifi_unit="24G";
var sel_wifi_unit="24G";
var product_name="Generic";
var def_product_name="";
var login_counter="10";
var sip_available=parseInt('0'+'',10);
var cfg_wantype='5';
addCfg("status_wifi_unit", "983044000000", "24G");
sel_wifi_unit=getCfg("status_wifi_unit");
if(sel_wifi_unit.indexOf("-")>=0)
wifi_unit=sel_wifi_unit.substr(0,sel_wifi_unit.indexOf('-'));
else
wifi_unit=sel_wifi_unit;
addCfg("uiLanguage", "327680000000", "en");
var rt_wan="GPON";
if(def_product_name!=""){
product_name=def_product_name;}
top.sip_available=sip_available;