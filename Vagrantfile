# -*- mode: ruby -*-
# vi: set ft=ruby :

# Vagrantfile API/syntax version. Don't touch unless you know what you're doing!
VAGRANTFILE_API_VERSION = "2"

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
  # Every Vagrant virtual environment requires a box to build off of.
  config.vm.box = "hashicorp/precise64"
  config.vm.network "forwarded_port", guest: 5000, host: 5000
  config.vm.network "private_network", ip: "192.168.33.100"

  # Share the home directory for access to host source code
  # and use NFS for 10-100x speedup:
  #config.vm.synced_folder "./", "/home/vagrant/golang/src/istio.io/istio", nfs: true, owner: "vagrant", group: "vagrant"

  # Now run manual shell script for additional provisioning:
  config.vm.provision "shell", path: "./bin/provision.sh"

end