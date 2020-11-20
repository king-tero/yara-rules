/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/

rule Trojan_Coin_Miner_a
{

  meta:
    description = "Trojan Coin Miner variant A - silently uses the infected device's physical resources to mine digital currency."
    source = "VTDIFF https://support.virustotal.com/hc/en-us/articles/360010904818-VTDIFF-Automatic-YARA-rules" 
    author = "king-tero"

  strings:
    $0 = {4E546AE97EDC1A0580FF0254CB84B5BAA6B96C8CF1D65028F67A6311F59BD39804B5060C7FF5919248C9F92FDDC631488237403DB80D276A534304BADA3838F728FB070E0AC9305BBB023BE8408D017FBC202F0BBDD1EFC4A98532D089CA1588C7D4BD360C6EF7EF63A4B3060E4A65509519AB415F387ED95365665098A8D1736BC98D41EF94E9EFCA6B40B7C144997FC07DC70486BBD48F7FD1590B4849BD87A8710803D63D07832A9D9948585930CD324A27D30397D97D}

  condition:
    all of them
}

rule Trojan_Coin_Miner_b
{
  meta:
    description = "Trojan Coin Miner variant B - silently uses the infected device's physical resources to mine digital currency."
    source = "VTDIFF https://support.virustotal.com/hc/en-us/articles/360010904818-VTDIFF-Automatic-YARA-rules"
    author = "king-tero"
    
  strings:
    $0 = {747A428A44F13A413AC2747085ED746C418807FFCD4A8B04C24D03F9418BF9468854F03A4584DB74534A8B04C2428A4CF03B413ACA744585ED744141880F418D7AF84A8B04C24D03F9FFCD468854F03B453AD975274A8B04C2428A4CF03C413ACA741985ED741541880F418D7AF94A8B04C24D03F9FFCD4688}
    $1 = {646F6E6174652E76322E786D7269672E636F6D}
  condition:
    all of them
}

rule Trojan_Coin_Miner_c
{
  meta:
    description = "Trojan Coin Miner variant C - silently uses the infected device's physical resources to mine digital currency."
    source = "VTDIFF https://support.virustotal.com/hc/en-us/articles/360010904818-VTDIFF-Automatic-YARA-rules"
    author = "king-tero"
    
  strings:
    $0 = {49567854665270764C6D4D6C5874566F517578524B7677756D5A634F7175586752766A6A424B444C6A507A594F7249665446566E7A526D65706F486B4A4276544A706463547961564C445A4D62746B57736C4C4C7A497078496A744B704A6E45654A6B484D67}
  condition:
    all of them
}

rule Trojan_Coin_Miner_d
{
  meta:
    description = "Trojan Coin Miner variant D - silently uses the infected device's physical resources to mine digital currency."
    source = "VTDIFF https://support.virustotal.com/hc/en-us/articles/360010904818-VTDIFF-Automatic-YARA-rules"
    author = "king-tero"
    
  strings:
    $0 = {5050483850505048203030384040383840605048384040403830485050504838403050484038403048403830405050483830404838506058403840384038304050684040384040403040405048302828386040282828282830282830302828302830283030302828282830303030303030202830283030282830303038482840482830282828283830284838282848402828283030}
  condition:
    all of them
}

rule Trojan_Coin_Miner_e
{
  meta:
    description = "Trojan Coin Miner variant E - silently uses the infected device's physical resources to mine digital currency."
    source = "VTDIFF https://support.virustotal.com/hc/en-us/articles/360010904818-VTDIFF-Automatic-YARA-rules"
    author = "king-tero"
    
  strings:
    $0 = {F8531EECF3F29ACCB392BB2C72720C3280266CF2C24C3A6CA08459546EFE724580F3FE05C79E5509EFEBA2C138B37DF345F64F45D271AB49F2724519A79413FED475EE14C9065440D7955308D5AC143C55}
  condition:
    all of them
}

