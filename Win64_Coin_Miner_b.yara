rule Win64_Coin_Miner_b
{
  strings:
    $0 = {49567854665270764C6D4D6C5874566F517578524B7677756D5A634F7175586752766A6A424B444C6A507A594F7249665446566E7A526D65706F486B4A4276544A706463547961564C445A4D62746B57736C4C4C7A497078496A744B704A6E45654A6B484D67}
  condition:
    all of them
}