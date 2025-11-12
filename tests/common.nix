{ pkgs }:

{
  configs.host = {
    services.nixtornet = {
      enable = true;
      tor = {
        enable = true;
        networks = [ "tornet" ];
      };

      networks.tornet = {
        name = "tornet";
        uuid = "12345678-abcd-1234-abcd-123456789abc";

        ip = {
          address = "192.168.100.1";
          netmask = "255.255.255.0";
          dhcp = {
            range = {
              start = "192.168.100.10";
              end = "192.168.100.100";
            };
          };
        };
      };
    };
  };
}
