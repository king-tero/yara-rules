rule PUA_DownloadGuide
{
  strings:
    $0 = {6EE1EA76871C4D45448EBE46C883069DC12AFE181F8EE402FAF3AB5D508A16310B9A06D0C57022CD492D5463CCB66E68460B53EACB4C24C0BC724EEAF115AEF4549A120AC37AB23360E2DA8955F32258F3DEDCCFEF8386A28C944F9F68F29890468427C776BFE3CC352C8B5E07646582C048B0A891F9619F762050A891C766B5EB78620356F08A1A13EA31A31EA099FD38F6F62732586F07F56BB8FB142BAFB7AACCD6635F738CDA0599A838A8CB17783651ACE99EF4783A8DCF0FD942E2980CAB2F9F0E01DEEF9F9949F12DDFAC744D1B98B547C5E529D1F99018C7629CBE83C7267B3E8A25C7C0DD9DE6356810209D8FD8DED2C3849C}
  condition:
    all of them
}
