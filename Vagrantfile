# -*- mode: ruby -*-
# vi: set ft=ruby :
#
# 0xLab-AD — Umbrella Corporation Active Directory Lab
# Automated vulnerable AD deployment for security research
#
# Usage: vagrant up
# Network: 192.168.56.0/24 (host-only)
#

DOMAIN        = "umbrella.corp"
DOMAIN_NETBIOS = "UMBRELLA"
DC_IP         = "192.168.56.10"
SRV_IP        = "192.168.56.11"
WS_IP         = "192.168.56.12"
WS02_IP       = "192.168.56.13"
WS03_IP       = "192.168.56.14"
WS04_IP       = "192.168.56.15"
UBSRV_IP      = "192.168.56.20"
KALI_IP       = "192.168.56.100"

# Shared administrator credentials for provisioning
ADMIN_USER    = "Administrator"
ADMIN_PASS    = "UmbrellaCorp2024!"

Vagrant.configure("2") do |config|

  # ---------- DC01 — Primary Domain Controller (Windows Server 2019) ----------
  config.vm.define "dc01", primary: true do |dc|
    dc.vm.box = "gusztavvargadr/windows-server-2019-standard"
    dc.vm.hostname = "DC01"
    dc.vm.network "private_network", ip: DC_IP, virtualbox__intnet: "umbrella_net"
    dc.vm.communicator = "winrm"
    dc.winrm.username = ADMIN_USER
    dc.winrm.password = ADMIN_PASS
    dc.winrm.transport = :plaintext
    dc.winrm.basic_auth_only = true
    dc.vm.boot_timeout = 900
    dc.vm.guest = :windows

    dc.vm.provider "virtualbox" do |vb|
      vb.name   = "0xLab-DC01"
      vb.memory = 4096
      vb.cpus   = 2
      vb.gui    = false
      vb.customize ["modifyvm", :id, "--clipboard", "bidirectional"]
      vb.customize ["modifyvm", :id, "--draganddrop", "bidirectional"]
    end

    dc.vm.provision "shell", path: "provisioning/dc01.ps1", args: [
      DOMAIN, DOMAIN_NETBIOS, ADMIN_PASS, DC_IP
    ]

    # After DC promotion and reboot, run AD setup
    dc.vm.provision "shell", path: "scripts/setup-ad.ps1", args: [
      DOMAIN, ADMIN_PASS
    ], reboot: true

    dc.vm.provision "shell", path: "scripts/setup-vulns.ps1", args: [
      DOMAIN
    ]
  end

  # ---------- SRV01 — File Server + IIS (Windows Server 2016) ----------
  config.vm.define "srv01" do |srv|
    srv.vm.box = "gusztavvargadr/windows-server-2016-standard"
    srv.vm.hostname = "SRV01"
    srv.vm.network "private_network", ip: SRV_IP, virtualbox__intnet: "umbrella_net"
    srv.vm.communicator = "winrm"
    srv.winrm.username = ADMIN_USER
    srv.winrm.password = ADMIN_PASS
    srv.winrm.transport = :plaintext
    srv.winrm.basic_auth_only = true
    srv.vm.boot_timeout = 900
    srv.vm.guest = :windows

    srv.vm.provider "virtualbox" do |vb|
      vb.name   = "0xLab-SRV01"
      vb.memory = 2048
      vb.cpus   = 2
      vb.gui    = false
    end

    srv.vm.provision "shell", path: "provisioning/srv01.ps1", args: [
      DOMAIN, DOMAIN_NETBIOS, ADMIN_PASS, DC_IP, SRV_IP
    ]
  end

  # ---------- WS01 — IT Workstation (Windows 10) ----------
  config.vm.define "ws01" do |ws|
    ws.vm.box = "gusztavvargadr/windows-10"
    ws.vm.hostname = "WS01"
    ws.vm.network "private_network", ip: WS_IP, virtualbox__intnet: "umbrella_net"
    ws.vm.communicator = "winrm"
    ws.winrm.username = ADMIN_USER
    ws.winrm.password = ADMIN_PASS
    ws.winrm.transport = :plaintext
    ws.winrm.basic_auth_only = true
    ws.vm.boot_timeout = 900
    ws.vm.guest = :windows

    ws.vm.provider "virtualbox" do |vb|
      vb.name   = "0xLab-WS01"
      vb.memory = 2048
      vb.cpus   = 2
      vb.gui    = false
    end

    ws.vm.provision "shell", path: "provisioning/ws01.ps1", args: [
      DOMAIN, DOMAIN_NETBIOS, ADMIN_PASS, DC_IP
    ]
  end

  # ---------- WS02 — HR Workstation (Windows 10) ----------
  config.vm.define "ws02" do |ws|
    ws.vm.box = "gusztavvargadr/windows-10"
    ws.vm.hostname = "WS02"
    ws.vm.network "private_network", ip: WS02_IP, virtualbox__intnet: "umbrella_net"
    ws.vm.communicator = "winrm"
    ws.winrm.username = ADMIN_USER
    ws.winrm.password = ADMIN_PASS
    ws.winrm.transport = :plaintext
    ws.winrm.basic_auth_only = true
    ws.vm.boot_timeout = 900
    ws.vm.guest = :windows

    ws.vm.provider "virtualbox" do |vb|
      vb.name   = "0xLab-WS02"
      vb.memory = 2048
      vb.cpus   = 2
      vb.gui    = false
    end

    ws.vm.provision "shell", path: "provisioning/ws01.ps1", args: [
      DOMAIN, DOMAIN_NETBIOS, ADMIN_PASS, DC_IP
    ]
  end

  # ---------- WS03 — Research Workstation (Windows 10) ----------
  config.vm.define "ws03" do |ws|
    ws.vm.box = "gusztavvargadr/windows-10"
    ws.vm.hostname = "WS03"
    ws.vm.network "private_network", ip: WS03_IP, virtualbox__intnet: "umbrella_net"
    ws.vm.communicator = "winrm"
    ws.winrm.username = ADMIN_USER
    ws.winrm.password = ADMIN_PASS
    ws.winrm.transport = :plaintext
    ws.winrm.basic_auth_only = true
    ws.vm.boot_timeout = 900
    ws.vm.guest = :windows

    ws.vm.provider "virtualbox" do |vb|
      vb.name   = "0xLab-WS03"
      vb.memory = 2048
      vb.cpus   = 2
      vb.gui    = false
    end

    ws.vm.provision "shell", path: "provisioning/ws01.ps1", args: [
      DOMAIN, DOMAIN_NETBIOS, ADMIN_PASS, DC_IP
    ]
  end

  # ---------- WS04 — Management Workstation (Windows 10) ----------
  config.vm.define "ws04" do |ws|
    ws.vm.box = "gusztavvargadr/windows-10"
    ws.vm.hostname = "WS04"
    ws.vm.network "private_network", ip: WS04_IP, virtualbox__intnet: "umbrella_net"
    ws.vm.communicator = "winrm"
    ws.winrm.username = ADMIN_USER
    ws.winrm.password = ADMIN_PASS
    ws.winrm.transport = :plaintext
    ws.winrm.basic_auth_only = true
    ws.vm.boot_timeout = 900
    ws.vm.guest = :windows

    ws.vm.provider "virtualbox" do |vb|
      vb.name   = "0xLab-WS04"
      vb.memory = 2048
      vb.cpus   = 2
      vb.gui    = false
    end

    ws.vm.provision "shell", path: "provisioning/ws01.ps1", args: [
      DOMAIN, DOMAIN_NETBIOS, ADMIN_PASS, DC_IP
    ]
  end

  # ---------- UBSRV01 — Linux Server (Ubuntu Server, domain-joined) ----------
  config.vm.define "ubsrv01" do |ub|
    ub.vm.box = "ubuntu/jammy64"
    ub.vm.hostname = "ubsrv01"
    ub.vm.network "private_network", ip: UBSRV_IP, virtualbox__intnet: "umbrella_net"
    ub.vm.boot_timeout = 600

    ub.vm.provider "virtualbox" do |vb|
      vb.name   = "0xLab-UBSRV01"
      vb.memory = 2048
      vb.cpus   = 2
      vb.gui    = false
    end

    ub.vm.provision "shell", path: "provisioning/ubsrv01.sh", args: [
      DOMAIN, DOMAIN_NETBIOS, ADMIN_PASS, DC_IP
    ]
  end

  # ---------- KALI — Attacker Machine (Kali Linux) ----------
  config.vm.define "kali" do |kali|
    kali.vm.box = "kalilinux/rolling"
    kali.vm.hostname = "kali"
    kali.vm.network "private_network", ip: KALI_IP, virtualbox__intnet: "umbrella_net"
    kali.vm.boot_timeout = 600

    kali.vm.provider "virtualbox" do |vb|
      vb.name   = "0xLab-KALI"
      vb.memory = 4096
      vb.cpus   = 2
      vb.gui    = false
    end

    kali.vm.synced_folder "attacker/", "/opt/0xlab", type: "rsync"

    kali.vm.provision "shell", inline: <<-SHELL
      set -e
      export DEBIAN_FRONTEND=noninteractive

      echo "[*] Updating package lists..."
      apt-get update -qq

      echo "[*] Installing offensive tools..."
      apt-get install -y -qq \
        python3-pip \
        nmap \
        enum4linux \
        smbclient \
        ldap-utils \
        crackmapexec \
        bloodhound \
        neo4j \
        hashcat \
        john \
        seclists \
        responder \
        evil-winrm \
        >/dev/null 2>&1

      echo "[*] Installing Python offensive tools..."
      pip3 install --quiet \
        impacket \
        bloodhound \
        ldapdomaindump \
        certipy-ad

      echo "[*] Setting up results directory..."
      mkdir -p /results
      chmod 777 /results

      echo "[*] Configuring /etc/hosts..."
      echo "#{DC_IP}  dc01.umbrella.corp dc01 umbrella.corp" >> /etc/hosts
      echo "#{SRV_IP}  srv01.umbrella.corp srv01"             >> /etc/hosts
      echo "#{WS_IP}  ws01.umbrella.corp ws01"               >> /etc/hosts
      echo "#{WS02_IP}  ws02.umbrella.corp ws02"              >> /etc/hosts
      echo "#{WS03_IP}  ws03.umbrella.corp ws03"              >> /etc/hosts
      echo "#{WS04_IP}  ws04.umbrella.corp ws04"              >> /etc/hosts
      echo "#{UBSRV_IP}  ubsrv01.umbrella.corp ubsrv01"      >> /etc/hosts

      echo "[*] Making attack scripts executable..."
      chmod +x /opt/0xlab/auto-enum.sh 2>/dev/null || true

      echo "[+] Kali attacker machine ready."
    SHELL
  end

end
