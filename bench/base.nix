{
  inputs,
  lib,
  pkgs,
  ...
}:

{
  nix = {
    channel.enable = false;
    nixPath = [ "nixpkgs=${pkgs.path}" ];

    settings = {
      accept-flake-config = true;
      allow-import-from-derivation = true;
      builders-use-substitutes = true;
      fallback = true;
      keep-build-log = true;
      keep-derivations = true;
      keep-env-derivations = true;
      keep-failed = true;
      keep-going = true;
      keep-outputs = true;
      sandbox = true;
      use-xdg-base-directories = true;
      warn-dirty = false;

      trusted-users = [
        "root"
        "@wheel"
      ];

      experimental-features = [
        "auto-allocate-uids"
        "ca-derivations"
        "cgroups"
        "flakes"
        "impure-derivations"
        "nix-command"
        "pipe-operators"
      ];

      substituters = lib.mkForce [
        "https://cache.ysun.co?priority=10"
        "https://cache.nixos.org?priority=15"
      ];

      trusted-public-keys = lib.mkForce [
        "cache.ysun.co-1:WxPYwT5g3kt9XhUhHPpNLZKI9HIOsVVAuqSHpok8Qt4="
        "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="
      ];
    };
  };

  environment = {
    variables.PAGER = "less -FRX";

    shells = with pkgs; [
      bashInteractive
      nushell
      zsh
    ];

    systemPackages = with pkgs; [
      bashInteractive
      nushell
      zsh

      # rfm
      inputs.self.packages.${pkgs.stdenv.hostPlatform.system}.default

      bcc
      bpftools
      bpftop
      bpftrace
      libbpf
      tcpdump
      trace-cmd
      xdp-tools

      alacritty.terminfo
      ethtool
      goflow2
      iperf3
      jq
      nfdump
      pmacct
      python3
      softflowd
      tcpreplay

      (callPackage ./hsflowd.nix { }) # in kernel sampling (EPCAP/TCX + PSAMPLE)
      (callPackage ./netobserv.nix { }) # in kernel per CPU hash aggregation
    ];
  };

  boot.supportedFilesystems.zfs = lib.mkForce false;
  boot.initrd.supportedFilesystems.zfs = lib.mkForce false;
}
