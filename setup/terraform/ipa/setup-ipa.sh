#!/bin/bash
set -o nounset
set -o errexit
set -o pipefail
set -o xtrace
trap 'echo Setup return code: $?' 0
BASE_DIR=$(cd $(dirname $0); pwd -L)

THE_PWD=Supersecret1

KEYTABS_DIR=/keytabs
REALM_NAME=WORKSHOP.COM
IPA_ADMIN_PASSWORD=$THE_PWD
DIRECTORY_MANAGER_PASSWORD=$THE_PWD
CM_PRINCIPAL_PASSWORD=$THE_PWD
USER_PASSWORD=$THE_PWD

CM_PRINCIPAL=cloudera-scm

USERS_GROUP=cdp-users
ADMINS_GROUP=cdp-admins

function log_status() {
  local msg=$1
  echo "STATUS:$msg"
}

# Often yum connection to Cloudera repo fails and causes the instance create to fail.
# yum timeout and retries options don't see to help in this type of failure.
# We explicitly retry a few times to make sure the build continues when these timeouts happen.
function yum_install() {
  local packages=$@
  local retries=10
  while true; do
    set +e
    yum install -d1 -y ${packages}
    RET=$?
    set -e
    if [[ ${RET} == 0 ]]; then
      break
    fi
    retries=$((retries - 1))
    if [[ ${retries} -lt 0 ]]; then
      echo 'YUM install failed!'
      exit 1
    else
      echo 'Retrying YUM...'
    fi
  done
}

function get_group_id() {
  local group=$1
  ipa group-find --group-name="$group" | grep GID | awk '{print $2}'
}

function add_groups() {
  while [[ $# -gt 0 ]]; do
    group=$1
    shift 1
    ipa group-add "$group" || true
  done
}

function add_user() {
  local princ=$1
  local homedir=$2
  shift 2

  # Add user, set password and get keytab
  if ipa user-show "$princ" >/dev/null 2>&1; then
    echo "-- User [$princ] already exists"
  else
    echo "-- Creating user [$princ]"
    local gid=$(get_group_id $1)
    echo clouderatemp | ipa user-add "$princ" --first="$princ" --last="User" --cn="$princ" --homedir="$homedir" --noprivate --gidnumber $gid --password || true
    kadmin.local change_password -pw ${USER_PASSWORD} $princ
  fi
  mkdir -p "${KEYTABS_DIR}"
  echo -e "${USER_PASSWORD}\n${USER_PASSWORD}" | ipa-getkeytab -p "$princ" -k "${KEYTABS_DIR}/${princ}.keytab" --password
  chmod 444 "${KEYTABS_DIR}/${princ}.keytab"

  # Create a jaas.conf file
  cat > ${KEYTABS_DIR}/jaas-${princ}.conf <<EOF
KafkaClient {
  com.sun.security.auth.module.Krb5LoginModule required
  useKeyTab=true
  keyTab="${KEYTABS_DIR}/${princ}.keytab"
  principal="${princ}@${REALM_NAME}";
};
EOF

  # Add user to groups
  while [[ $# -gt 0 ]]; do
    group=$1
    shift 1
    ipa group-add-member "$group" --users="$princ" || true
  done
}

function get_os_type() {
  if grep "^NAME=.*Red Hat Enterprise Linux" /etc/os-release > /dev/null 2>&1; then
    echo "RHEL"
  elif grep -i "^NAME=.*centos" /etc/os-release > /dev/null 2>&1; then
    echo "CENTOS"
  else
    echo "UNKNOWN"
  fi
}

function get_os_major_version() {
  grep "^VERSION=" /etc/os-release 2> /dev/null | sed 's/VERSION=["'\'']//g' | grep -o "^."
}

function patch_yum_repos_for_centos() {
  # In July 2024 Centos 7 reached EoL and the repo was moved to the CentOS Vault.
  # The mirrorlist.centos.org host was also decommissioned.
  # The commands below update YUM repo file accordingly, if needed
  if [[ $(get_os_type) == "CENTOS" ]]; then
    sed -i s/mirror.centos.org/vault.centos.org/g /etc/yum.repos.d/*.repo
    sed -i s/^#.*baseurl=http/baseurl=http/g /etc/yum.repos.d/*.repo
    sed -i s/^mirrorlist=http/#mirrorlist=http/g /etc/yum.repos.d/*.repo
  fi
}

log_status "Setting host and domain names"
export PRIVATE_IP=$(hostname -I | awk '{print $1}')
export LOCAL_HOSTNAME=$(hostname -f)
export PUBLIC_IP=$(curl -sL http://ifconfig.me || curl -sL http://api.ipify.org/ || curl -sL https://ipinfo.io/ip)
export PUBLIC_DNS=ipa.${PUBLIC_IP}.nip.io
export DOMAIN_NAME=${PUBLIC_IP}.nip.io

sed -i.bak "/${LOCAL_HOSTNAME}/d;/^${PRIVATE_IP}/d;/^::1/d" /etc/hosts
echo "$PRIVATE_IP $PUBLIC_DNS $LOCAL_HOSTNAME" >> /etc/hosts

sed -i.bak '/kernel.domainname/d' /etc/sysctl.conf
echo "kernel.domainname=${PUBLIC_DNS#*.}" >> /etc/sysctl.conf
sysctl -p

hostnamectl set-hostname $PUBLIC_DNS
if [[ -f /etc/sysconfig/network ]]; then
  sed -i "/HOSTNAME=/ d" /etc/sysconfig/network
fi
echo "HOSTNAME=${PUBLIC_DNS}" >> /etc/sysconfig/network

log_status "Installing IPA server"
yum erase -y epel-release || true; rm -f /etc/yum.repos.r/epel* || true
if [[ $(get_os_major_version) == "8" || $(get_os_major_version) == "9" ]]; then
  # dnf config-manager --set-enabled powertools
  # dnf -y install epel-release epel-next-release
  dnf -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-$(get_os_major_version).noarch.rpm
else
  # In July 2024 Centos 7 reached EoL and the repo was moved to the CentOS Vault.
  # The commands below update YUM repo file accordingly, if needed
  patch_yum_repos_for_centos
  yum_install epel-release
  # The EPEL repo has intermittent refresh issues that cause errors like the one below.
  # Switch to baseurl to avoid those issues when using the metalink option.
  # Error: https://.../repomd.xml: [Errno -1] repomd.xml does not match metalink for epel
  sed -i 's/metalink=/#metalink=/;s/#*baseurl=/baseurl=/' /etc/yum.repos.d/epel*.repo
fi

# Install IPA using Ansible
yum clean all
yum -y install krb5-devel gcc-c++ rust

# Install python39
if [[ $(get_os_major_version) == "7" ]]; then
  yum -y install openssl-devel openssl11-devel bzip2-devel libffi-devel wget
  wget https://www.python.org/ftp/python/3.9.18/Python-3.9.18.tgz -O /tmp/python39.tgz
  tar -xvf /tmp/python39.tgz -C /tmp > /dev/null
  cd /tmp/Python-3.9.18/
  ./configure --enable-optimizations --with-lto
  make altinstall
  export PATH=/usr/local/bin:$PATH
elif [[ $(get_os_major_version) == "8" ]]; then
  yum -y module enable idm:DL1
  yum -y install python39-devel platform-python-setuptools python3-requests
elif [[ $(get_os_major_version) == "9" ]]; then
  yum -y install python3-devel platform-python-setuptools python3-requests
fi

python3.9 -m venv /tmp/ipa
cd /tmp/ipa
source "/tmp/ipa/bin/activate"
pip3 install --upgrade pip
pip3 install ansible-core setuptools setuptools_rust ipapython
ansible-galaxy collection install freeipa.ansible_freeipa

cat > ansible.cfg <<EOF
[defaults]
roles_path        = /root/.ansible/collections/ansible_collections/freeipa/ansible_freeipa/roles
library           = /root/.ansible/collections/ansible_collections/freeipa/ansible_freeipa/plugins/modules
module_utils      = /root/.ansible/collections/ansible_collections/freeipa/ansible_freeipa/plugins/module_utils
inventory_plugins = /root/.ansible/collections/ansible_collections/freeipa/ansible_freeipa/plugins/inventory
EOF

cat > inventory<<EOF
[ipaserver]
$PUBLIC_DNS
[ipaserver:vars]
ipaserver_domain=$DOMAIN_NAME
ipaserver_realm=$REALM_NAME
ipaserver_setup_dns=true
ipaserver_auto_forwarders=true
ipaadmin_password=$THE_PWD
ipadm_password=$THE_PWD
ipaserver_ca_subject=CN=$PUBLIC_DNS
ipaserver_install_packages=true
ipaserver_allow_zone_overlap=true
EOF

cat > install-server.yml<<EOF
---
- name: Playbook to configure IPA server
  hosts: ipaserver
  become: true

  roles:
    - role: ipaserver
      state: present
EOF

ansible-playbook -c local -i inventory install-server.yml

log_status "Change kadmin Realm"
echo "*/admin@WORKSHOP.COM	*" > /var/kerberos/krb5kdc/kadm5.acl
systemctl restart kadmin

log_status "Open kadmin port"
firewall-cmd --permanent --add-service=kadmin
firewall-cmd --reload

# Renewable tickets
kadmin.local -q "modprinc -maxrenewlife 14d krbtgt/$REALM_NAME"
sed -i 's/default_principal_flags.*/&, +renewable/' /var/kerberos/krb5kdc/kdc.conf
systemctl restart krb5kdc

# End of ansible automation
yum_install cowsay figlet rng-tools realmd cockpit
systemctl enable --now cockpit.socket
echo "${THE_PWD}" | passwd root --stdin

# authenticate as admin
echo "${IPA_ADMIN_PASSWORD}" | kinit admin >/dev/null

log_status "Creating groups"
add_groups $USERS_GROUP $ADMINS_GROUP shadow supergroup hue

# added for ECS (ipausers group is reserved, use cdp-users as default)
log_status "Default group is ${USERS_GROUP}"
ipa config-mod --defaultgroup="$USERS_GROUP"

log_status "Creating Cloudera Manager principal user and adding it to admins group"
add_user admin /home/admin admins $ADMINS_GROUP $USERS_GROUP "trust admins" shadow supergroup

kinit -kt "${KEYTABS_DIR}/admin.keytab" admin
ipa krbtpolicy-mod --maxlife=604800 --maxrenew=604800 || true

log_status "Creating LDAP bind user"
add_user ldap_bind_user /home/ldap_bind_user $USERS_GROUP

log_status "Creating HUE proxy user"
add_user hue /home/hue hue $USERS_GROUP

log_status "Creating other users"
add_user workshop /home/workshop $USERS_GROUP
add_user alice /home/alice $USERS_GROUP
add_user bob /home/bob $USERS_GROUP

log_status "Adding required roles"
# Add this role to avoid racing conditions between multiple CMs coming up at the same time
ipa role-add cmadminrole
ipa role-add-privilege cmadminrole --privileges="Service Administrators" --privileges="Host Administrators"

log_status "Starting the IPA service"
systemctl restart krb5kdc
systemctl enable ipa

log_status "Configuring and starting rng-tools"
echo 'EXTRAOPTIONS="-i -r /dev/urandom"' >> /etc/sysconfig/rngd
systemctl start rngd

log_status "Ensuring that SElinux is turned off now and at reboot"
setenforce 0
sed -i 's/SELINUX=.*/SELINUX=disabled/' /etc/selinux/config

log_status "Making keytabs and CA cert available through the web server"
ln -s /keytabs /var/www/html/keytabs
ln -s /etc/ipa/ca.crt /var/www/html/ca.crt

log_status "Add keytab folder to SELinux"
semanage fcontext -a -t httpd_sys_rw_content_t "/keytabs(/.*)?"
restorecon -R "/keytabs"

if [[ $(get_os_type) == "CENTOS" ]]; then
  export COWPATH=/usr/share/cowsay
else
  export COWPATH=/usr/share/cowsay/cows
fi
figlet -f small -w 300  "IPA server deployed successfully"'!' | cowsay -n -f "$(ls -1 $COWPATH | grep "\.cow" | sed 's/\.cow//' | egrep -v "bong|head-in|sodomized|telebears" | shuf -n 1)"
echo "Completed successfully: IPA"
log_status "IPA server installed successfully."