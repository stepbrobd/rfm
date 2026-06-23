{ pkgs, ... }:

{
  boot.kernelModules = [ "vfio-pci" ];

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
