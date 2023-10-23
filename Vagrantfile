# Read the branch's Go version from the .go-version file.
GO_VERSION = File.read(File.join(File.dirname(__FILE__), ".go-version")).strip
GOLANGCI_LINT_VERSION = '1.44.2'

create_symlink = <<SCRIPT
echo "Creating go-libaudit symlink in $HOME"
cd $HOME
if [ -d "/vagrant" ] && [ ! -e "go-libaudit" ]; then ln -s /vagrant go-libaudit; fi
SCRIPT

install_gvm = <<SCRIPT
mkdir -p ~/bin
if [ ! -e "~/bin/gvm" ]; then
  curl -sL -o ~/bin/gvm https://github.com/andrewkroh/gvm/releases/download/v0.5.2/gvm-linux-amd64
  chmod +x ~/bin/gvm
  ~/bin/gvm #{GO_VERSION}
  echo 'export GOPATH=$HOME/go' >> ~/.bash_profile
  echo 'export PATH=$HOME/bin:$GOPATH/bin:$PATH' >> ~/.bash_profile
  echo 'eval "$(gvm #{GO_VERSION})"' >> ~/.bash_profile
fi

SCRIPT

install_golangci_lint = <<SCRIPT
curl -sL -O https://github.com/golangci/golangci-lint/releases/download/v#{GOLANGCI_LINT_VERSION}/golangci-lint-#{GOLANGCI_LINT_VERSION}-linux-amd64.deb
export DEBIAN_FRONTEND=noninteractive
dpkg -i ./golangci-lint-#{GOLANGCI_LINT_VERSION}-linux-amd64.deb
rm -f golangci-lint-#{GOLANGCI_LINT_VERSION}-linux-amd64.deb
SCRIPT

Vagrant.configure(2) do |config|
  config.vm.box = "ubuntu/mantic64"
  config.vm.network :forwarded_port, guest: 22, host: 2228, id: "ssh", auto_correct: true
  config.vm.provision "shell", inline: create_symlink, privileged: false
  config.vm.provision "shell", inline: install_gvm, privileged: false
  config.vm.provision "shell", inline: install_golangci_lint, privileged: true
  config.vm.provision "shell", inline: "apt-get update && apt-get install -y make gcc python3 python3-pip python3-venv git auditd"
  config.vm.provision "shell", inline: "systemctl stop auditd"
  config.vm.provision "shell", inline: "systemctl disable auditd"
end
