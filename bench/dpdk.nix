{ lib, pkgs, ... }:

{
  boot.kernelModules = [ "vfio-pci" ];

  nixpkgs.overlays = [
    (
      _: prev:
      # dpdk have intel-ipsec-mb (x86 only) in buildInputs unconditionally
      # drop after https://github.com/nixos/nixpkgs/pull/534604
      lib.optionalAttrs (!prev.stdenv.hostPlatform.isx86_64) {
        dpdk = prev.dpdk.override { intel-ipsec-mb = null; };
      }
    )
  ];

  boot.kernelParams = [
    # iommu for vfio-pci binding
    "intel_iommu=on"
    "amd_iommu=on"
    "iommu=pt"
    # 1g hugepages for dpdk mempools 8g for now bump if need more
    "default_hugepagesz=1G"
    "hugepagesz=1G"
    "hugepages=8"
  ];

  environment.systemPackages = with pkgs; [
    dpdk
    pktgen
    rdma-core
  ];
}
