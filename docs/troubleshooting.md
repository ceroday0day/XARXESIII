# Troubleshooting Guide

This guide covers common issues when deploying the 0xLab-AD environment and their solutions.

---

## WinRM Authorization Error

### Symptoms

```
An authorization error occurred while connecting to WinRM.

User: Administrator
Endpoint: http://127.0.0.1:55985/wsman
Message: WinRM::WinRMAuthorizationError
```

This error occurs during `vagrant up` when Vagrant tries to connect to Windows VMs (DC01, SRV01, WS01-WS04) for provisioning.

### Root Causes

1. **WinRM Service Not Ready**: Windows boxes take time to fully initialize WinRM after boot
2. **Network Configuration Delay**: The private network may not be fully established when Vagrant attempts connection
3. **Box Version Issues**: Older cached box versions may have WinRM configuration issues
4. **Timeout Too Short**: Default WinRM timeouts may be insufficient for slower systems

### Solutions

#### Solution 1: Update Vagrant Boxes (Recommended)

Remove cached boxes and download the latest versions:

```bash
# Remove old Windows Server 2019 box
vagrant box remove gusztavvargadr/windows-server-2019-standard

# Remove old Windows Server 2016 box
vagrant box remove gusztavvargadr/windows-server-2016-standard

# Remove old Windows 10 box
vagrant box remove gusztavvargadr/windows-10

# Re-download latest versions
vagrant box add gusztavvargadr/windows-server-2019-standard
vagrant box add gusztavvargadr/windows-server-2016-standard
vagrant box add gusztavvargadr/windows-10

# Start deployment with fresh boxes
vagrant up
```

#### Solution 2: Increase WinRM Timeouts (Already Configured)

The Vagrantfile has been updated with extended WinRM timeout settings:

```ruby
dc.winrm.timeout = 1800        # 30 minutes total timeout
dc.winrm.retry_limit = 30      # Retry up to 30 times
dc.winrm.retry_delay = 10      # Wait 10 seconds between retries
```

These settings allow Vagrant to wait up to 30 minutes for WinRM to become available, with automatic retry logic.

#### Solution 3: Destroy and Rebuild

If the error persists after updating boxes:

```bash
# Completely destroy all VMs
vagrant destroy -f

# Remove any stale VirtualBox VMs manually
VBoxManage list vms | grep "0xLab" | cut -d'"' -f2 | xargs -I {} VBoxManage unregistervm "{}" --delete

# Start fresh
vagrant up
```

#### Solution 4: Provision Machines Individually

Instead of bringing up all machines at once, provision them one at a time:

```bash
# Start with DC01 (required first)
vagrant up dc01

# Wait for DC01 to fully provision, then start SRV01
vagrant up srv01

# Continue with workstations
vagrant up ws01
vagrant up ws02
vagrant up ws03
vagrant up ws04

# Ubuntu Server
vagrant up ubsrv01

# Attacker machine
vagrant up kali
```

#### Solution 5: Check VirtualBox Networking

Ensure VirtualBox host-only networking is properly configured:

```bash
# List VirtualBox host-only networks
VBoxManage list hostonlyifs

# You should see a network with IP 192.168.56.1
# If not, create it:
VBoxManage hostonlyif create
VBoxManage hostonlyif ipconfig vboxnet0 --ip 192.168.56.1 --netmask 255.255.255.0
```

---

## Slow Provisioning

### Symptoms

Provisioning takes longer than 45 minutes, or machines appear to hang during setup.

### Solutions

#### Increase System Resources

Ensure your host system meets the minimum requirements:

- **RAM**: 24 GB minimum (32 GB recommended)
  - Calculation: DC01 (4 GB) + SRV01 (2 GB) + 4× WS (8 GB) + UBSRV01 (2 GB) + Kali (4 GB) = 20 GB for VMs + 4 GB for host OS = 24 GB minimum
- **CPU**: 8 cores minimum
- **Disk**: 200 GB free space

#### Adjust VM Resources

Edit the `Vagrantfile` to reduce resource allocation if your system is constrained.

Find the VM definition block and modify the provider settings:

```ruby
# Example: Reduce DC01 memory from 4096 MB to 2048 MB
config.vm.define "dc01", primary: true do |dc|
  # ... other configuration ...
  
  dc.vm.provider "virtualbox" do |vb|
    vb.name   = "0xLab-DC01"
    vb.memory = 2048  # Changed from 4096
    vb.cpus   = 1     # Changed from 2
    vb.gui    = false
  end
end
```

**Note**: Reducing resources may affect lab performance and some attacks may not work correctly.

#### Enable VirtualBox GUI

To monitor what's happening during provisioning, enable the GUI:

```ruby
vb.gui = true  # Change from false to true
```

---

## Domain Join Failures

### Symptoms

```
Failed to join domain umbrella.corp
```

### Solutions

1. **Verify DC01 is Running**: Ensure DC01 is fully provisioned before joining other machines
   ```bash
   vagrant status dc01
   ```

2. **Check DNS Resolution**: From a workstation, verify DNS is working:
   ```bash
   vagrant winrm ws01 -c "nslookup umbrella.corp"
   ```

3. **Verify Network Connectivity**: Test ping to DC01:
   ```bash
   vagrant winrm ws01 -c "ping -n 4 192.168.56.10"
   ```

4. **Re-provision**: If DNS or network fails, re-provision the affected machine:
   ```bash
   vagrant reload ws01 --provision
   ```

---

## Network Connectivity Issues

### Symptoms

Machines cannot communicate with each other, or Kali cannot reach domain resources.

### Solutions

#### Check VirtualBox Internal Network

All machines should be on the `umbrella_net` internal network:

```bash
# Check network configuration
VBoxManage showvminfo 0xLab-DC01 | grep "Internal"
VBoxManage showvminfo 0xLab-SRV01 | grep "Internal"
```

#### Verify IP Addresses

Check that all machines have their assigned IPs:

| Machine | IP Address | 
|---------|------------|
| DC01 | 192.168.56.10 |
| SRV01 | 192.168.56.11 |
| WS01 | 192.168.56.12 |
| WS02 | 192.168.56.13 |
| WS03 | 192.168.56.14 |
| WS04 | 192.168.56.15 |
| UBSRV01 | 192.168.56.20 |
| Kali | 192.168.56.100 |

From Kali:
```bash
vagrant ssh kali
ping 192.168.56.10  # Should reach DC01
```

#### Restart Networking

If connectivity fails, restart VirtualBox networking:

```bash
vagrant halt
VBoxManage list hostonlyifs  # Verify host-only network exists
vagrant up
```

---

## Box Download Failures

### Symptoms

```
Failed to download box from <URL>
The box failed to unpack properly.
```

### Solutions

1. **Check Internet Connection**: Ensure you have stable internet access
2. **Clear Vagrant Cache**: 
   ```bash
   rm -rf ~/.vagrant.d/tmp/*
   ```
3. **Manual Download**: Download boxes manually from [Vagrant Cloud](https://app.vagrantup.com/boxes/search)
4. **Use Mirror**: Some boxes may be available from alternative sources

---

## Insufficient System Resources

### Symptoms

```
VirtualBox error: VERR_OUT_OF_MEMORY
Failed to allocate X MB of memory
```

### Solutions

1. **Deploy Subset of Machines**: Start with just DC01, SRV01, WS01, and Kali
   ```bash
   vagrant up dc01 srv01 ws01 kali
   ```

2. **Close Other Applications**: Free up RAM by closing browsers, IDEs, etc.

3. **Enable Swap/Pagefile**: Ensure your OS has adequate swap space configured

---

## Additional Resources

- [Vagrant Documentation](https://www.vagrantup.com/docs)
- [VirtualBox Manual](https://www.virtualbox.org/manual/)
- [gusztavvargadr Boxes](https://app.vagrantup.com/gusztavvargadr)

---

## Getting Help

If you continue experiencing issues:

1. **Check Logs**: 
   ```bash
   vagrant up --debug &> vagrant.log
   ```

2. **Open an Issue**: Include:
   - Output of `vagrant version`
   - Output of `VBoxManage --version`
   - Output of `vagrant status`
   - Relevant error messages
   - Your host OS and specifications

3. **Community**: Search for similar issues in the Vagrant/VirtualBox communities
