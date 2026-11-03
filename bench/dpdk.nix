{ pkgs, ... }:

{
  boot.kernelModules = [ "vfio-pci" ];

  boot.kernelParams = [
    "intel_iommu=on"
    "amd_iommu=on"
    "iommu=pt"
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
