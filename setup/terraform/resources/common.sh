#!/bin/bash

KEYTABS_DIR=/keytabs
KAFKA_CLIENT_PROPERTIES=${KEYTABS_DIR}/kafka-client.properties
KRB_REALM=WORKSHOP.COM
OPENJDK_ARCHIVE=https://jdk.java.net/archive/
JDK_BASE=/usr/lib/jvm

export THE_PWD=Supersecret1
export THE_PWD_HASH_PRE719SP1="8ef2932408095916dc440fbbb18e60f2f5ef42ada16527b917c3d830475de7bb"
export THE_PWD_SALT_PRE719SP1="1762354682113328521"
export THE_PWD_HASH_719SP1="{SHA-256}{YA09jLzq5Vk7oz5mM01o7UAT1NlOPBTB7y+RU7u2O/E=}5a07f3c3986cfc4e97a51792e832699278942d52f8ddef0c27c612d33667ca89"
export THE_PWD_SALT_719SP1="-999999"


[[ ! -f $BASE_DIR/the_pwd.txt ]] && echo -n "$THE_PWD" > $BASE_DIR/the_pwd.txt || true

# CA details
SEC_BASE=/opt/cloudera/security
export CA_DIR=${SEC_BASE}/ca
export CA_KEY=$CA_DIR/ca-key.pem
export CA_KEY_PWD=${THE_PWD}
export CA_CONF=$CA_DIR/openssl.cnf
export CA_EMAIL=admin@cloudera.com
export ROOT_PEM=$CA_DIR/ca-cert.pem

export KEY_PEM=${SEC_BASE}/x509/key.pem
export UNENCRYTED_KEY_PEM=${SEC_BASE}/x509/unencrypted-key.pem
export CSR_PEM=${SEC_BASE}/x509/host.csr
export HOST_PEM=${SEC_BASE}/x509/host.pem
export KEY_PWD=${THE_PWD}
export KEYSTORE_PWD=$KEY_PWD
export TRUSTSTORE_PWD=${THE_PWD}

# Generated files
export CERT_PEM=${SEC_BASE}/x509/cert.pem
export TRUSTSTORE_PEM=${SEC_BASE}/x509/truststore.pem
export KEYSTORE_JKS=${SEC_BASE}/jks/keystore.jks
export TRUSTSTORE_JKS=${SEC_BASE}/jks/truststore.jks

LICENSE_FILE_PATH=${BASE_DIR}/.license
PG_VERSION=15

# Make scripts executable
chmod +x $BASE_DIR/*.sh > /dev/null 2>&1 || true

# Load cluster metadata
PUBLIC_DNS=${PUBLIC_DNS:-dummy}
if [[ -f /etc/workshop.conf ]]; then
  set -a
  source /etc/workshop.conf
  set +a
fi

function log_status() {
  local msg=$1
  echo "STATUS:$msg"
}

function is_kerberos_enabled() {
  echo $ENABLE_KERBEROS
}

function is_tls_enabled() {
  echo $ENABLE_TLS
}

function get_cm_base_url() {
  if [ "$(is_tls_enabled)" == "yes" ]; then
    echo "https://${CLUSTER_HOST}:7183"
  else
    echo "http://${CLUSTER_HOST}:7180"
  fi
}

function get_kafka_port() {
  if [ "$(is_tls_enabled)" == "yes" ]; then
    echo "9093"
  else
    echo "9092"
  fi
}

function get_kafka_security_protocol() {
  if [ "$(is_kerberos_enabled)" == "yes" ]; then
    if [ "$(is_tls_enabled)" == "yes" ]; then
      echo "SASL_SSL"
    else
      echo "SASL_PLAINTEXT"
    fi
  else
    if [ "$(is_tls_enabled)" == "yes" ]; then
      echo "SSL"
    else
      echo "PLAINTEXT"
    fi
  fi
}

function get_create_cluster_tls_option() {
  if [[ $(openssl s_client -connect localhost:7183 </dev/null 2> /dev/null | grep -c CONNECTED) -gt 0 ]]; then
    echo "--tls-ca-cert $TRUSTSTORE_PEM"
  else
    echo ""
  fi
}
# Often yum connection to Cloudera repo fails and causes the instance create to fail.
# yum timeout and retries options don't see to help in this type of failure.
# We explicitly retry a few times to make sure the build continues when these timeouts happen.
function yum_install() {
  local packages=$@
  local retries=60
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
      sleep 1
      echo 'Retrying YUM...'
    fi
  done
}

function get_homedir() {
  local username=$1
  getent passwd $username | cut -d: -f6
}

function get_stack_file() {
  local namespace=$1
  local base_dir=$2
  local exclude_signed=${3:-no}
  for stack in $base_dir/stack.${namespace}.sh \
               $base_dir/stack.sh; do
    local signed_stack_file="${stack}.signed.el$(get_os_major_version)"
    if [ "${exclude_signed}" == "no" -a -e "$signed_stack_file" ]; then
      stack="$signed_stack_file"
      break
    elif [ -e "${stack}" ]; then
      break
    fi
  done
  echo "$stack"
}

function load_stack() {
  local namespace=$1
  local base_dir=${2:-$BASE_DIR}
  local validate_only=${3:-no}
  local exclude_signed=${4:-}
  local stack_file=$(get_stack_file $namespace $base_dir $exclude_signed)

  # Set MAJOR_OS_VERSION before sourcing the stack
  export MAJOR_OS_VERSION=$(get_os_major_version)

  source $stack_file
  # export all stack vars
  for var_name in $(grep -h "^[A-Z0-9_]*=" $stack_file | sed 's/=.*//' | sort -u); do
    eval "export $var_name"
  done
  CM_SERVICES=$(echo "$CM_SERVICES" | tr "[a-z]" "[A-Z]")
  # set service selection flags
  for svc_name in $(echo "$CM_SERVICES" | tr "," " "); do
    eval "export HAS_${svc_name}=1"
  done
  # check for Kerberos
  ENABLE_KERBEROS=$(echo "${ENABLE_KERBEROS:-NO}" | tr a-z A-Z)
  if [ "$ENABLE_KERBEROS" == "YES" -o "$ENABLE_KERBEROS" == "TRUE" -o "$ENABLE_KERBEROS" == "1" ]; then
    ENABLE_KERBEROS=yes
  else
    ENABLE_KERBEROS=no
  fi
  KERBEROS_TYPE=$(echo "${KERBEROS_TYPE:-MIT}" | tr a-z A-Z)
  if [ "$KERBEROS_TYPE" == "IPA" ]; then
    TF_VAR_use_ipa=true
    USE_IPA=yes
  else
    TF_VAR_use_ipa=false
    USE_IPA=no
  fi
  ENABLE_TLS=$(echo "${ENABLE_TLS:-NO}" | tr a-z A-Z)
  if [ "$ENABLE_TLS" == "YES" -o "$ENABLE_TLS" == "TRUE" -o "$ENABLE_TLS" == "1" ]; then
    ENABLE_TLS=yes
  else
    ENABLE_TLS=no
  fi
  if [[ "${CEM_URL:-}" == "" && "${EFM_TARBALL_URL:-}${MINIFI_TARBALL_URL:-}" == "" ]]; then
    export HAS_CEM=0
  else
    export HAS_CEM=1
  fi

  # Set default for ANACONDA_PRODUCT, which was introduced late
  ANACONDA_PRODUCT=${ANACONDA_PRODUCT:-Anaconda}

  # Ensure deployment works with legacy stacks
  if [[ -z "${CDP_PARCEL_URLS[@]:-}" && ! -z "${PARCEL_URLS[@]:-}" ]]; then
    CDP_PARCEL_URLS=(${PARCEL_URLS[@]})
  fi
  if [[ -z "${CDP_CSD_URLS[@]:-}" && ! -z "${CSD_URLS[@]:-}" ]]; then
    CDP_CSD_URLS=(${CSD_URLS[@]})
  fi

  export ENABLE_KERBEROS ENABLE_TLS KERBEROS_TYPE USE_IPA TF_VAR_use_ipa PROJECT_ZIP_FILE HAS_CEM ANACONDA_PRODUCT CDP_PARCEL_URLS CDP_CSD_URLS
  prepare_keytabs_dir
}

function prepare_keytabs_dir() {
  if [ "$validate_only" == "no" ]; then
    mkdir -p $KEYTABS_DIR

    # Create a client properties file for Kafka clients
    if [[ $(is_kerberos_enabled) == yes && $(is_tls_enabled) == yes ]]; then
      cat > ${KAFKA_CLIENT_PROPERTIES} <<EOF
security.protocol=SASL_SSL
sasl.mechanism=GSSAPI
sasl.kerberos.service.name=kafka
ssl.truststore.location=$TRUSTSTORE_JKS
ssl.truststore.password=$THE_PWD
sasl.jaas.config=com.sun.security.auth.module.Krb5LoginModule required useTicketCache=true;
EOF
    elif [[ $(is_kerberos_enabled) == yes ]]; then
      cat > ${KAFKA_CLIENT_PROPERTIES} <<EOF
security.protocol=SASL_PLAINTEXT
sasl.mechanism=GSSAPI
sasl.kerberos.service.name=kafka
sasl.jaas.config=com.sun.security.auth.module.Krb5LoginModule required useTicketCache=true;
EOF
    elif [[ $(is_tls_enabled) == yes ]]; then
      cat > ${KAFKA_CLIENT_PROPERTIES} <<EOF
security.protocol=SSL
ssl.truststore.location=$TRUSTSTORE_JKS
ssl.truststore.password=$THE_PWD
EOF
    fi

    # Create a jaas.conf file
    if [[ $(is_kerberos_enabled) == yes ]]; then
      cat > ${KEYTABS_DIR}/jaas.conf <<EOF
KafkaClient {
  com.sun.security.auth.module.Krb5LoginModule required
  useTicketCache=true;
};
EOF
    fi

  fi
}

function check_vars() {
  local stack_file=$1; shift
  local errors=0
  while [ $# -gt 0 ]; do
    local var_name=$1; shift
    if [ "$(eval "echo \${${var_name}:-}")" == "" ]; then
      echo "ERROR: The required property ${var_name} is not set" > /dev/stderr
      errors=1
    fi
  done
  echo $errors
}

function get_remote_repo_username() {
  if [[ ! -z ${REMOTE_REPO_USR:-} ]]; then
    echo "${REMOTE_REPO_USR}"
    return
  fi
  if [[ -s $LICENSE_FILE_PATH ]]; then
    grep '"uuid"' "$LICENSE_FILE_PATH" | awk -F\" '{printf "%s", $4}'
  fi
}

function get_remote_repo_password() {
  if [[ ! -z ${REMOTE_REPO_PWD:-} ]]; then
    echo "${REMOTE_REPO_PWD}"
    return
  fi
  if [[ -s $LICENSE_FILE_PATH ]]; then
    local name=$(grep '"name"' "$LICENSE_FILE_PATH" | awk -F\" '{print $4}')
    echo -n "${name}$(get_remote_repo_username)" | openssl dgst -sha256 -hex | egrep -o '[a-f0-9]{12}' | head -1
  fi
}

function validate_stack() {
  local namespace=$1
  local base_dir=${2:-$BASE_DIR}
  local license_file_path=${3:-}
  export LICENSE_FILE_PATH=${license_file_path:-${LICENSE_FILE_PATH:-}}
  local stack_file=$(get_stack_file $namespace $base_dir exclude-signed)
  load_stack "$namespace" "$base_dir" validate_only exclude-signed
  errors=0

  # validate required variables
  if [ "$(check_vars "$stack_file" \
            CDH_MAJOR_VERSION CM_MAJOR_VERSION CM_SERVICES \
            ENABLE_KERBEROS MAVEN_BINARY_URL)" != "0" ]; then
    errors=1
  fi

  if [[ -z ${JAVA_PACKAGE_NAME:-} && -z ${OPENJDK_VERSION:-} ]]; then
    echo "${C_RED}ERROR: One of the following properties must be specified in the stack:" > /dev/stderr
    echo "         - JAVA_PACKAGE_NAME" > /dev/stderr
    echo "           OR" > /dev/stderr
    echo "         - OPENJDK_VERSION${C_NORMAL}" > /dev/stderr
    errors=1
  fi

  if [ "${HAS_CDSW:-}" == "1" ]; then
    if [ "$(check_vars "$stack_file" \
              CDSW_BUILD CDSW_CSD_URL)" != "0" ]; then
      errors=1
    fi
  fi

  if [[ "${CDH_VERSION}" == *"6."* || "${CDH_VERSION}" == *"7.0."* || "${CDH_VERSION}" == *"7.1.0"* ]]; then
    if [ "${HAS_SCHEMAREGISTRY:-}" == "1" -o "${HAS_SMM:-}" == "1" -o "${HAS_SRM:-}" == "1" ]; then
      if [ "$(check_vars "$stack_file" \
                CSP_PARCEL_REPO SCHEMAREGISTRY_CSD_URL \
                STREAMS_MESSAGING_MANAGER_CSD_URL \
                STREAMS_REPLICATION_MANAGER_CSD_URL)" != "0" ]; then
        errors=1
      fi
    fi
  fi

  if [ "${HAS_NIFI:-}" == "1" ]; then
    if [ "$(check_vars "$stack_file" \
              CFM_NIFIREG_CSD_URL CFM_NIFI_CSD_URL)" != "0" ]; then
      errors=1
    fi
  fi

  if [ "${HAS_FLINK:-}" == "1" ]; then
    if [ "$(check_vars "$stack_file" FLINK_CSD_URL)" != "0" ]; then
      errors=1
    fi
  fi

  if [[ ! ("${CEM_URL:-}" == "" && "${EFM_TARBALL_URL:-}${MINIFI_TARBALL_URL:-}" == "") ]]; then
    export HAS_CEM=1
    if [[ "${CEM_URL:-}" != "" && "${EFM_TARBALL_URL:-}${MINIFI_TARBALL_URL:-}" != "" ]]; then
      echo "${C_RED}ERROR: The following parameter combinations are mutually exclusive:" > /dev/stderr
      echo "         - CEM_URL must be specified" > /dev/stderr
      echo "           OR" > /dev/stderr
      echo "         - EFM_TARBALL_URL and MINIFI_TARBALL_URL must be specified${C_NORMAL}" > /dev/stderr
      errors=1
    fi
  fi

  if [ ! \( "${CM_BASE_URL:-}" != "" -a "${CM_REPO_FILE_URL:-}" != "" -a "${CM_REPO_AS_TARBALL_URL:-}" == "" \) -a \
       ! \( "${CM_BASE_URL:-}${CM_REPO_FILE_URL:-}" == "" -a "${CM_REPO_AS_TARBALL_URL:-}" != "" \) ]; then
    echo "${C_RED}ERROR: The following parameter combinations are mutually exclusive:" > /dev/stderr
    echo "         - CM_BASE_URL and CM_REPO_FILE_URL must be specified" > /dev/stderr
    echo "           OR" > /dev/stderr
    echo "         - CM_REPO_AS_TARBALL_URL must be specified${C_NORMAL}" > /dev/stderr
    errors=1
  fi

  set -- "${CDP_PARCEL_URLS[@]:-}" "${CDP_CSD_URLS[@]:-}"
  local has_paywall_url=0
  while [ $# -gt 0 ]; do
    local url=$1; shift
    if [[ "$url" == *"/p/"* ]]; then
      has_paywall_url=1
      break
    fi
  done
  if [ "$has_paywall_url" == "1" ]; then
    if [ "$(get_remote_repo_password)" == "" -o "$(get_remote_repo_username)" == "" ]; then
      echo "${C_RED}ERROR: TF_VAR_cdp_license_file must be specified when using paywall URLs.${C_NORMAL}" > /dev/stderr
      errors=1
    fi
  fi
  # HAS_ECS
  if [ "${HAS_ECS:-}" == "1" ]; then
    if [[ $(is_kerberos_enabled) == "yes" ]] && [[ $(is_tls_enabled) == "yes" ]]; then
      if [[ $USE_IPA == "no" ]]; then
        echo "${C_RED}ERROR: ECS requires IPA to be enabled.${C_NORMAL}" > /dev/stderr 
        errors=1
      else
        local stack_cm7_version=$(echo $CM_VERSION | sed 's/\.//g')
        local stack_ecs_version=$(echo $ECS_VERSION | sed 's/\.//g')
        if [[ $stack_ecs_version -ge 152 ]] && [[ $stack_cm7_version -lt 71132 ]]; then
          echo "${C_RED}ERROR: ECS 1.5.2+ requires Cloudera Manager version 7.11.3.2+.${C_NORMAL}" > /dev/stderr 
          errors=1
        fi
        if [[ $TF_VAR_pvc_data_services == "false" ]]; then
          echo "${C_RED}ERROR: ECS requires TF_VAR_pvc_data_services to be true.${C_NORMAL}" > /dev/stderr 
          errors=1
        fi       
      fi
    else
      echo "${C_RED}ERROR: ECS requires TLS and Kerberos to be enabled.${C_NORMAL}" > /dev/stderr 
      errors=1
    fi
  fi

  if [ "$errors" != "0" ]; then
    echo "${C_RED}ERROR: Please fix the errors above in the configuration file $stack_file and try again.${C_NORMAL}" > /dev/stderr
    exit 1
  fi
}

function check_for_presigned_url() {
  local url="$1"
  url_file="$(get_stack_file $NAMESPACE $BASE_DIR exclude-signed).urls.el$(get_os_major_version)"
  signed_url=""
  if [ -s "$url_file" ]; then
    signed_url="$(fgrep "${url}-->" "$url_file" | sed 's/.*-->//')"
  fi
  if [ "$signed_url" != "" ]; then
    echo "$signed_url"
  else
    echo "$url"
  fi
}

function auth() {
  local princ=$1
  local username=${princ%%/*}
  username=${username%%@*}
  local keytab_file=${KEYTABS_DIR}/${username}.keytab
  if [ -f $keytab_file ]; then
    export KRB5CCNAME=/tmp/workshop.${username}
    kinit -kt $keytab_file $princ
    export KAFKA_OPTS="-Djava.security.auth.login.config=${KEYTABS_DIR}/jaas.conf"
  else
    export HADOOP_USER_NAME=$username
  fi
}

function unauth() {
  if [[ $(is_kerberos_enabled) == yes ]]; then
    kdestroy || true
    unset KAFKA_OPTS
  else
    unset HADOOP_USER_NAME
  fi
}

function add_user() {
  local princ=$1
  local homedir=$2
  local groups=${3:-}

  if [[ $USE_IPA == "yes" ]]; then
    echo "Skipping creation of local user [$princ] since we're using a central IPA server"
    return
  fi

  # Ensure OS user exists
  local username=${princ%%/*}
  username=${username%%@*}
  if [ "$(getent passwd $username > /dev/null && echo exists || echo does_not_exist)" == "does_not_exist" ]; then
    useradd -U $username -d $homedir
    echo -e "${THE_PWD}\n${THE_PWD}" | passwd $username
  fi

  # Add user to groups
  if [[ $groups != "" ]]; then
    # Ensure groups exist
    for group in $(echo "$groups" | sed 's/,/ /g'); do
      groupadd -f $group
    done
    usermod -G $groups $username
  fi

  if [ "$(is_kerberos_enabled)" == "yes" ]; then
    # Create Kerberos principal
    (sleep 1 && echo -e "${THE_PWD}\n${THE_PWD}") | /usr/sbin/kadmin.local -q "addprinc $princ"
    mkdir -p ${KEYTABS_DIR}

    # Create keytab
    echo -e "addent -password -p $princ -k 0 -e aes256-cts\n${THE_PWD}\nwrite_kt ${KEYTABS_DIR}/$username.keytab" | ktutil
    chmod 444 ${KEYTABS_DIR}/$username.keytab

    # Create a jaas.conf file
    cat > ${KEYTABS_DIR}/jaas-${username}.conf <<EOF
KafkaClient {
  com.sun.security.auth.module.Krb5LoginModule required
  useKeyTab=true
  keyTab="${KEYTABS_DIR}/${username}.keytab"
  principal="${princ}@${KRB_REALM}";
};
EOF
  fi
}

function install_ipa_client() {
  local ipa_host=$1
  if [[ $ipa_host == "" ]]; then
    echo "ERROR: No IPA server detected."
    exit 1
  fi

  # Install IPA client package
  log_status "Installing IPA client packages"
  # Enable idm client stream for RHEL 8
  if [[ $MAJOR_OS_VERSION == "8" ]]; then
    yum -y module enable idm:DL1/client 
  fi
  yum_install ipa-client openldap-clients krb5-workstation krb5-libs

  wait_for_ipa "$ipa_host"

  # Install IPA client
  log_status "Installing IPA client"
  ipa-client-install \
    --principal=admin \
    --password="$THE_PWD" \
    --server="$IPA_HOST" \
    --realm="$KRB_REALM" \
    --domain="$(echo $ipa_host | sed 's/^[^.]*\.//')" \
    --force-ntpd \
    --ssh-trust-dns \
    --all-ip-addresses \
    --ssh-trust-dns \
    --unattended \
    --mkhomedir \
    --force-join

  systemctl stop ntpd || true
  systemctl disable ntpd || true
  systemctl restart chronyd || true

  # Enable enumeration for the SSSD client, so that Ranger Usersync can see users/groups
  sed -i.bak 's/^\[domain.*/&\
enumerate = True\
ldap_enumeration_refresh_timeout = 50/;'\
's/^\[nss\].*/&\
enum_cache_timeout = 45/' /etc/sssd/sssd.conf
  systemctl restart sssd
  sleep 60 # wait a bit and do it a second time for good measure
  systemctl restart sssd

  # Adjust krb5.conf
  sed -i 's/udp_preference_limit.*/udp_preference_limit = 1/;/KEYRING/d;/KCM/d' /etc/krb5.conf
  if [[ -d /etc/krb5.conf.d/ ]]; then
    find /etc/krb5.conf.d/ \( -type f -o -type l \) -exec egrep -l "KEYRING|KCM" {} \; | xargs -I{} sed -i '/KEYRING/d;/KCM/d' {}
  fi

  # Copy keytabs from IPA server
  rm -rf /tmp/keytabs
  wget --recursive --no-parent --no-host-directories "http://${IPA_HOST}/keytabs/" -P /tmp/keytabs
  mv /tmp/keytabs/keytabs/* ${KEYTABS_DIR}/
  find ${KEYTABS_DIR} -name "index.html*" -delete
  chmod 755 ${KEYTABS_DIR}
  chmod -R 444 ${KEYTABS_DIR}/*

  # Add IPA cert to Java's default truststore
  local java_home cacerts
  java_home=$(readlink -f "$(dirname "$(readlink -f "$(which java)")")/..")
  cacerts=$(readlink -f "$(find -L "$java_home" -name cacerts)")
  keytool -importcert -keystore "$cacerts" -storepass changeit -alias ipa-ca-cert -file /etc/ipa/ca.crt -noprompt

  # The enctype order on Centos 8 changes and it breaks a few things. Fix this here.
  if [[ -f /usr/share/crypto-policies/policies/DEFAULT.pol && -d /etc/crypto-policies/policies/ ]]; then
    ipa-getkeytab --permitted-enctypes # check permitted enctypes before the change
    sed -E 's/(mac@Kerberos *= *)(.*[^ ])  *HMAC-SHA1/\1HMAC-SHA1 \2/g' /usr/share/crypto-policies/policies/DEFAULT.pol > /etc/crypto-policies/policies/CDP.pol
    update-crypto-policies --set CDP
    ipa-getkeytab --permitted-enctypes # check permitted enctypes after the change
  fi
}

function install_kerberos() {
  krb_server=$(hostname -f)
  krb_realm_lc=$( echo $KRB_REALM | tr A-Z a-z )

  # Install Kerberos packages
  yum_install krb5-libs krb5-server krb5-workstation

  # Ensure entropy
  yum_install rng-tools
  systemctl start rngd
  cat /proc/sys/kernel/random/entropy_avail

  # Update krb5.conf
  cat > /etc/krb5.conf <<EOF
[logging]
 default = FILE:/var/log/krb5libs.log
 kdc = FILE:/var/log/krb5kdc.log
 admin_server = FILE:/var/log/kadmind.log

[libdefaults]
 dns_lookup_realm = false
 ticket_lifetime = 24h
 renew_lifetime = 7d
 forwardable = true
 rdns = false
 pkinit_anchors = FILE:/etc/pki/tls/certs/ca-bundle.crt
 default_realm = $KRB_REALM
 udp_preference_limit = 1

[realms]
 $KRB_REALM = {
  kdc = $krb_server
  admin_server = $krb_server
 }

[domain_realm]
 .$krb_realm_lc = $KRB_REALM
 $krb_realm_lc = $KRB_REALM
EOF

  # Update kdc.conf
  cat > /var/kerberos/krb5kdc/kdc.conf <<EOF
[kdcdefaults]
 kdc_ports = 88
 kdc_tcp_ports = 88

[realms]
 $KRB_REALM = {
  max_renewable_life = 7d 0h 0m 0s
  #master_key_type = aes256-cts
  acl_file = /var/kerberos/krb5kdc/kadm5.acl
  dict_file = /usr/share/dict/words
  admin_keytab = /var/kerberos/krb5kdc/kadm5.keytab
  supported_enctypes = aes256-cts:normal aes128-cts:normal des3-hmac-sha1:normal arcfour-hmac:normal camellia256-cts:normal camellia128-cts:normal des-hmac-sha1:normal des-cbc-md5:normal des-cbc-crc:normal
 }
EOF

  # Create database
  /usr/sbin/kdb5_util create -s -P ${THE_PWD}

  # Update kadm5.acl
  cat > /var/kerberos/krb5kdc/kadm5.acl <<EOF
*/admin@$KRB_REALM    *
EOF

  # Create CM principal
  add_user scm/admin /home/scm

  # Set maxrenewlife for krbtgt
  # IMPORTANT: You must explicitly set this, even if the default is already set correctly.
  #            Failing to do so will cause some services to fail.

  kadmin.local -q "modprinc -maxrenewlife 7day krbtgt/$KRB_REALM@$KRB_REALM"

  # Start Kerberos
  systemctl enable krb5kdc
  systemctl enable kadmin
  systemctl start krb5kdc
  systemctl start kadmin

  # Add service principals
  add_user hdfs /var/lib/hadoop-hdfs
  add_user yarn /var/lib/hadoop-yarn
  add_user kafka /var/lib/kafka
  add_user flink /var/lib/flink
}

function create_ca() {
  if [[ -s $ROOT_PEM ]]; then
    return
  fi

  mkdir -p $CA_DIR/newcerts
  touch $CA_DIR/index.txt
  echo "unique_subject = no" > $CA_DIR/index.txt.attr
  hexdump -n 16 -e '4/4 "%08X" 1 "\n"' /dev/random > $CA_DIR/serial

  # Generate CA key
  openssl genrsa \
    -out ${CA_KEY} \
    -aes256 \
    -passout pass:${CA_KEY_PWD} \
    2048
  chmod 400 ${CA_KEY}

  # Create the CA configuration
  cat > $CA_CONF <<EOF
HOME = ${CA_DIR}
RANDFILE = ${CA_DIR}/.rnd

[ ca ]
default_ca = CertToolkit # The default ca section

[ CertToolkit ]
dir = $HOME
database = $CA_DIR/index.txt # database index file.
serial = $CA_DIR/serial # The current serial number
new_certs_dir = $CA_DIR/newcerts # default place for new certs.
certificate = $ROOT_PEM # The CA certificate
private_key = $CA_KEY # The private key
default_md = sha256 # use public key default MD
unique_subject = no # Set to 'no' to allow creation of
# several ctificates with same subject.
policy = policy_any
preserve = no # keep passed DN ordering
default_days = 4000

name_opt = ca_default # Subject Name options
cert_opt = ca_default # Certificate field options

copy_extensions = copy

[ req ]
default_bits = 2048
default_md = sha256
distinguished_name = req_distinguished_name
string_mask = utf8only

[ req_distinguished_name ]
countryName_default = XX
countryName_min = 2
countryName_max = 2
localityName_default = Default City
0.organizationName_default = Default Company Ltd
commonName_max = 64
emailAddress_max = 64

[ policy_any ]
countryName = optional
stateOrProvinceName = optional
localityName = optional
organizationName = optional
organizationalUnitName = optional
commonName = supplied
emailAddress = optional

[ v3_common_extensions ]

[ v3_user_extensions ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer

[ v3_ca_extensions ]
basicConstraints = CA:TRUE
subjectAltName=email:${CA_EMAIL}
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
EOF

  # Generate CA certificate
  openssl req -x509 -new -nodes \
    -sha256 \
    -key ${CA_KEY} \
    -days 4000 \
    -out ${ROOT_PEM} \
    -passin pass:${CA_KEY_PWD} \
    -passout pass:${CA_KEY_PWD} \
    -extensions v3_ca_extensions \
    -config ${CA_CONF} \
    -subj '/C=US/ST=California/L=San Francisco/O=Cloudera/OU=PS/CN=CertToolkitRootCA'
}

function ensure_cm_user() {
  if ! getent passwd cloudera-scm > /dev/null 2>&1 ; then
    useradd -U cloudera-scm
  fi
  if ! getent group cloudera-scm > /dev/null 2>&1 ; then
    groupadd cloudera-scm
  fi
}

function wait_for_ipa() {
  local ipa_host=$1
  local retries=300
  while [[ $retries -gt 0 ]]; do
    set +e
    ret=$(curl -s -o /dev/null -w "%{http_code}" "http://${ipa_host}/ca.crt")
    err=$?
    set -e
    if [[ $err == 0 && $ret == "200" ]]; then
      break
    fi
    retries=$((retries - 1))
    sleep 5
    log_status "Waiting for IPA to be ready (retries left: $retries)"
  done
}

function create_certs() {
  local ipa_host=$1

  mkdir -p $(dirname $KEY_PEM) $(dirname $CSR_PEM) $(dirname $HOST_PEM) ${SEC_BASE}/jks

  # Create private key
  openssl genrsa -des3 -out ${KEY_PEM} -passout pass:${KEY_PWD} 2048

  # Create CSR
  local public_ip=$(get_public_ip)
  ALT_NAMES=""
  if [[ ! -z ${LOCAL_HOSTNAME:-} ]]; then
    ALT_NAMES="DNS:${LOCAL_HOSTNAME},"
  fi
  export ALT_NAMES="${ALT_NAMES}DNS:$(hostname -f),DNS:*.${public_ip}.nip.io,DNS:*.cdsw.${public_ip}.nip.io"
  # HAS_ECS: Add ECS SAN
  if [[ ${HAS_ECS:-0} == 1 ]] && [[ $PUBLIC_DNS == ecs* ]]; then
    ALT_NAMES="${ALT_NAMES},DNS:*.apps.${PUBLIC_DNS},DNS:edge2ai.apps.${PUBLIC_DNS},DNS:*.edge2ai.apps.${PUBLIC_DNS}"
  fi
  export ALT_NAMES
  openssl req\
    -new\
    -key ${KEY_PEM} \
    -subj "/C=US/ST=California/L=San Francisco/O=Cloudera/OU=PS/CN=$(hostname -f)" \
    -out ${CSR_PEM} \
    -passin pass:${KEY_PWD} \
    -config <( cat <<EOF
[ req ]
default_bits = 2048
default_md = sha256
distinguished_name = req_distinguished_name
req_extensions = v3_user_req
string_mask = utf8only

[ req_distinguished_name ]
countryName_default = XX
countryName_min = 2
countryName_max = 2
localityName_default = Default City
0.organizationName_default = Default Company Ltd
commonName_max = 64
emailAddress_max = 64

[ v3_user_req ]
basicConstraints = CA:FALSE
subjectKeyIdentifier = hash
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = $ALT_NAMES
EOF
  )

  # Create an unencrypted version of the key (required for CDSW internal termination)
  openssl rsa -in "$KEY_PEM" -passin pass:"$KEY_PWD" > "$UNENCRYTED_KEY_PEM"

  # Sign cert
  if [[ $ipa_host != "" ]]; then
    kinit -kt $KEYTABS_DIR/admin.keytab admin
    if [[ ! -z ${LOCAL_HOSTNAME:-} ]]; then
      ipa host-add-principal $(hostname -f) "host/${LOCAL_HOSTNAME}"
    fi
    ipa host-add-principal $(hostname -f) "host/*.${public_ip}.nip.io"
    ipa host-add-principal $(hostname -f) "host/*.cdsw.${public_ip}.nip.io"
    # HAS_ECS: Add principals
    if [[ ${HAS_ECS:-0} == 1 ]] && [[ $PUBLIC_DNS == ecs* ]]; then
      ipa host-add-principal $(hostname -f) "host/*.apps.${PUBLIC_DNS}"
      ipa host-add-principal $(hostname -f) "host/edge2ai.apps.${PUBLIC_DNS}"
      ipa host-add-principal $(hostname -f) "host/*.edge2ai.apps.${PUBLIC_DNS}"
    fi
    ipa cert-request ${CSR_PEM} --principal=host/$(hostname -f)
    echo -e "-----BEGIN CERTIFICATE-----\n$(ipa host-find $(hostname -f) | grep Certificate: | tail -1 | awk '{print $NF}')\n-----END CERTIFICATE-----" | openssl x509 > ${HOST_PEM}

    # Wait for IPA to be ready and download IPA cert
    mkdir -p $(dirname $ROOT_PEM)
    wait_for_ipa "$ipa_host"
    log_status "Downloading IPA CA certificate"
    curl -s -o $ROOT_PEM -w "%{http_code}" "http://${ipa_host}/ca.crt"
    if [[ ! -s $ROOT_PEM ]]; then
      echo "ERROR: Cannot download the IPA CA certificate"
      exit 1
    fi
  else
    create_ca

    openssl ca \
      -config ${CA_CONF} \
      -in ${CSR_PEM} \
      -key ${CA_KEY_PWD} \
      -batch \
      -extensions v3_user_extensions | \
    openssl x509 > ${HOST_PEM}
  fi

  # Create PEM truststore
  rm -f $TRUSTSTORE_PEM
  cp $ROOT_PEM $TRUSTSTORE_PEM

  # Create PEM combined certificate
  cp $HOST_PEM $CERT_PEM

  # Generate JKS keystore
  rm -f temp.p12

  openssl pkcs12 -export \
   -in $CERT_PEM \
   -inkey <(openssl rsa -in $KEY_PEM -passin pass:$KEY_PWD) \
   -out temp.p12 \
   -passout pass:temptemptemp \
   -name $(hostname -f)

  rm -f $KEYSTORE_JKS
  keytool \
   -importkeystore \
   -alias $(hostname -f) \
   -srcstoretype PKCS12 \
   -srckeystore temp.p12 \
   -destkeystore $KEYSTORE_JKS \
   -srcstorepass temptemptemp \
   -deststorepass $KEYSTORE_PWD \
   -destkeypass $KEYSTORE_PWD

  rm -f temp.p12

  # Generate JKS truststore
  # HAS_ECS: Add store type JKS as newer JDK defaults to PKCS12, ensure compat with ECS 1.5.3+
  rm -f $TRUSTSTORE_JKS
  for cert in $ROOT_PEM; do
    if [[ -s $cert ]]; then
      keytool \
        -importcert \
        -keystore $TRUSTSTORE_JKS \
        -storetype JKS \
        -storepass $TRUSTSTORE_PWD \
        -file $cert \
        -alias $(basename $cert) \
        -trustcacerts \
        -no-prompt
    fi
  done

  # Create agent password file
  ensure_cm_user
  echo $KEY_PWD > ${SEC_BASE}/x509/pwfile
  chown root:root ${SEC_BASE}/x509/pwfile
  chmod 400 ${SEC_BASE}/x509/pwfile

  # Create HUE LB password file
  mkdir -p ${SEC_BASE}/hue
  echo $KEY_PWD > ${SEC_BASE}/hue/loadbalancer.pw
  chmod 755 ${SEC_BASE}/hue
  chmod 444 ${SEC_BASE}/hue/loadbalancer.pw

  # Create copies of the stores (needed by NiFi in CDP < 7.1.6 due to hard-coded names in the CSD)
  groupadd -r nifi || true
  /usr/sbin/useradd -r -m -g nifi -K UMASK=022 --home /var/lib/nifi --comment NiFi --shell /bin/bash nifi || true
  cp --force $KEYSTORE_JKS /var/lib/nifi/cm-auto-host_keystore.jks
  cp --force $TRUSTSTORE_JKS /var/lib/nifi/cm-auto-in_cluster_truststore.jks
  chmod 444 /var/lib/nifi/cm-auto-host_keystore.jks /var/lib/nifi/cm-auto-in_cluster_truststore.jks
  chown nifi:nifi /var/lib/nifi/cm-auto-host_keystore.jks /var/lib/nifi/cm-auto-in_cluster_truststore.jks

  # Set permissions
  chown root:root $KEY_PEM $KEYSTORE_JKS $CERT_PEM $TRUSTSTORE_PEM $TRUSTSTORE_JKS
  chmod 400 $KEY_PEM $UNENCRYTED_KEY_PEM $KEYSTORE_JKS
  chmod 444 $CERT_PEM $TRUSTSTORE_PEM $TRUSTSTORE_JKS

  # Prepare key+cert for ShellInABox
  local sib_dir=/var/lib/shellinabox
  if [[ -d $sib_dir ]]; then
    local sib_cert=${sib_dir}/certificate.pem
    openssl rsa -in "$KEY_PEM" -passin pass:"$KEY_PWD" > $sib_cert
    cat $CERT_PEM $ROOT_PEM >> $sib_cert
    chown shellinabox:shellinabox $sib_cert
    chmod 400 $sib_cert
    rm -f ${sib_dir}/certificate-{localhost,${CLUSTER_HOST}}.pem
    ln -s $sib_cert ${sib_dir}/certificate-localhost.pem
    ln -s $sib_cert ${sib_dir}/certificate-${CLUSTER_HOST}.pem
    if [[ ! -z ${LOCAL_HOSTNAME:-} ]]; then
      rm -f ${sib_dir}/certificate-${LOCAL_HOSTNAME}.pem
      ln -s $sib_cert ${sib_dir}/certificate-${LOCAL_HOSTNAME}.pem
    fi
  fi

  tighten_keystores_permissions
}

function tighten_keystores_permissions() {
  # Set permissions for HUE LB password file
  set +e # Just in case some of the users do not exist

  chown -R hue:hue ${SEC_BASE}/hue
  chmod 500 ${SEC_BASE}/hue
  chmod 400 ${SEC_BASE}/hue/loadbalancer.pw

  # Set permissions and ACLs
  chmod 440 $KEY_PEM $KEYSTORE_JKS

  setfacl -m user:cloudera-scm:r--,group:cloudera-scm:r-- $KEYSTORE_JKS
  setfacl -m user:atlas:r--,group:atlas:r-- $KEYSTORE_JKS
  setfacl -m user:cruisecontrol:r--,group:cruisecontrol:r-- $KEYSTORE_JKS
  setfacl -m user:flink:r--,group:flink:r-- $KEYSTORE_JKS
  setfacl -m user:hbase:r--,group:hbase:r-- $KEYSTORE_JKS
  setfacl -m user:hdfs:r--,group:hdfs:r-- $KEYSTORE_JKS
  setfacl -m user:hive:r--,group:hive:r-- $KEYSTORE_JKS
  setfacl -m user:httpfs:r--,group:httpfs:r-- $KEYSTORE_JKS
  setfacl -m user:impala:r--,group:impala:r-- $KEYSTORE_JKS
  setfacl -m user:kafka:r--,group:kafka:r-- $KEYSTORE_JKS
  setfacl -m user:knox:r--,group:knox:r-- $KEYSTORE_JKS
  setfacl -m user:livy:r--,group:livy:r-- $KEYSTORE_JKS
  setfacl -m user:nifi:r--,group:nifi:r-- $KEYSTORE_JKS
  setfacl -m user:nifiregistry:r--,group:nifiregistry:r-- $KEYSTORE_JKS
  setfacl -m user:oozie:r--,group:oozie:r-- $KEYSTORE_JKS
  setfacl -m user:ranger:r--,group:ranger:r-- $KEYSTORE_JKS
  setfacl -m user:schemaregistry:r--,group:schemaregistry:r-- $KEYSTORE_JKS
  setfacl -m user:solr:r--,group:solr:r-- $KEYSTORE_JKS
  setfacl -m user:spark:r--,group:spark:r-- $KEYSTORE_JKS
  setfacl -m user:streamsmsgmgr:r--,group:streamsmsgmgr:r-- $KEYSTORE_JKS
  setfacl -m user:streamsrepmgr:r--,group:streamsrepmgr:r-- $KEYSTORE_JKS
  setfacl -m user:yarn:r--,group:hadoop:r-- $KEYSTORE_JKS
  setfacl -m user:zeppelin:r--,group:zeppelin:r-- $KEYSTORE_JKS
  setfacl -m user:zookeeper:r--,group:zookeeper:r-- $KEYSTORE_JKS
  setfacl -m user:ssb:r--,group:ssb:r-- $KEYSTORE_JKS

  setfacl -m user:cloudera-scm:r--,group:cloudera-scm:r-- $KEY_PEM
  setfacl -m user:postgres:r--,group:postgres:r-- $KEY_PEM
  setfacl -m user:hue:r--,group:hue:r-- $KEY_PEM
  setfacl -m user:impala:r--,group:impala:r-- $KEY_PEM
  setfacl -m user:kudu:r--,group:kudu:r-- $KEY_PEM
  setfacl -m user:streamsmsgmgr:r--,group:streamsmsgmgr:r-- $KEY_PEM
  setfacl -m user:ssb:r--,group:ssb:r-- $KEY_PEM

  setfacl -m user:cloudera-scm:r--,group:cloudera-scm:r-- ${SEC_BASE}/x509/pwfile
  setfacl -m user:ssb:r--,group:ssb:r-- ${SEC_BASE}/x509/pwfile

  # Due to changes in 7.1.8 Hue needs write permissions on the cert dir
  # TODO: Remove this when CDPD-44355 gets resolved
  setfacl -m user:hue:rwx,group:hue:rwx /opt/cloudera/security/x509/

  set -e
}

function wait_for_cm() {
  echo "-- Wait for CM to be ready before proceeding"
  # TLS: Check if is_tls_enabled = "yes"
  if [[ "${1:-no}" == "no" ]]; then
    api_url='http://localhost:7180/api/version'
  else
    api_url='https://localhost:7183/api/version'
  fi
  while true; do
    for pwd in admin ${THE_PWD}; do
      local result=$(
        curl \
          --fail \
          --head \
          --insecure \
          --location-trusted \
          --output /dev/null \
          --silent \
          --user "admin:${pwd}" \
          --write-out "%{http_code}" \
          "${api_url}"
      )
      if [[ $result == "200" ]]; then
        break 2
      fi
    done
    echo "waiting 10s for CM to come up.."
    sleep 10
  done
  echo "-- CM has finished starting"
}

function retry_if_needed() {
  local retries=$1
  local wait_secs=$2
  local cmd=$3
  local ret=0
  while [[ $retries -ge 0 ]]; do
    reset_errexit=false
    if [[ -o errexit ]]; then
      set +e
      reset_errexit=true
    fi
    eval "$cmd"
    ret=$?
    "$reset_errexit" && set -e
    if [[ $ret -eq 0 ]]; then
      return 0
    else
      retries=$((retries-1))
      if [[ $retries -lt 0 ]]; then
        return $ret
      fi
    fi
    sleep $wait_secs
    echo "Retrying command [$cmd]"
  done
}

#
# Template parsing functions
#

function service_port() {
  local template_file=$1
  local service_type=$2
  local role_type=$3
  local non_tls_config=$4
  local tls_config=${5:-}

  if [[ $tls_config == "" || $ENABLE_TLS != "yes" ]]; then
    local config=$non_tls_config
  else
    local config=$tls_config
  fi
  if [[ $role_type != "" ]]; then
    jq -r '.services[] | select(.serviceType == "'"$service_type"'").roleConfigGroups[] | select(.roleType == "'"$role_type"'").configs[] | select(.name == "'"$config"'").value' $template_file
  else
    jq -r '.services[] | select(.serviceType == "'"$service_type"'").serviceConfigs[] | select(.name == "'"$config"'").value' $template_file
  fi
}

function get_service_urls() {
  local tmp_template_file=/tmp/template.$$
  load_stack $NAMESPACE $BASE_DIR/resources validate_only exclude_signed
  CLUSTER_HOST=dummy PRIVATE_IP=dummy PUBLIC_DNS=dummy DOCKER_DEVICE=dummy CDSW_DOMAIN=dummy \
  IPA_HOST="$([[ $USE_IPA == "yes" ]] && echo dummy || echo "")" \
  CLUSTER_ID=dummy PEER_CLUSTER_ID=dummy PEER_PUBLIC_DNS=dummy ECS_PUBLIC_DNS=dummy \
  python $BASE_DIR/resources/cm_template.py --cdh-major-version $CDH_MAJOR_VERSION $CM_SERVICES > $tmp_template_file

  local cm_port=$([[ $ENABLE_TLS == "yes" ]] && echo 7183 || echo 7180)
  local protocol=$([[ $ENABLE_TLS == "yes" ]] && echo https || echo http)
  (
    echo "CM=Cloudera Manager=${protocol}://{host}:${cm_port}/"
    (
      if [[ $CDH_VERSION < "7.1.7" ]]; then
        echo "EFM=Edge Flow Manager=http://{host}:10088/efm/ui/"
      else
        echo "EFM=Edge Flow Manager=${protocol}://{host}:10088/efm/ui/"
      fi
      if [[ ${HAS_FLINK:-0} == 1 ]]; then
        local flink_version=$(jq -r '.products[] | select(.product == "FLINK").version' $tmp_template_file | sed 's/.*csa//;s/-.*//;s/[a-z]//g')
        local is_ge_17=$([[ $(echo -e "1.7.0.0\n$flink_version" | sort -V | head -1) == "1.7.0.0" ]] && echo yes || echo no)
        local flink_port=$(service_port $tmp_template_file FLINK FLINK_HISTORY_SERVER historyserver_web_port)
        echo "FLINK=Flink Dashboard=${protocol}://{host}:${flink_port}/"
        local ssb_port=""
        [[ $is_ge_17 == "yes" ]] && ssb_port=$(service_port $tmp_template_file SQL_STREAM_BUILDER STREAMING_SQL_ENGINE server.port server.port)
        [[ $ssb_port == "" ]] && ssb_port=$(service_port $tmp_template_file SQL_STREAM_BUILDER STREAMING_SQL_CONSOLE console.port console.secure.port)
        echo "SSB=SQL Stream Builder=${protocol}://{host}:${ssb_port}/"
      fi
      if [[ ${HAS_NIFI:-0} == 1 ]]; then
        local nifi_port=$(service_port $tmp_template_file NIFI NIFI_NODE nifi.web.http.port nifi.web.https.port)
        local nifireg_port=$(service_port $tmp_template_file NIFIREGISTRY NIFI_REGISTRY_SERVER nifi.registry.web.http.port nifi.registry.web.https.port)
        echo "NIFI=NiFi=${protocol}://{host}:${nifi_port}/nifi/"
        echo "NIFIREG=NiFi Registry=${protocol}://{host}:${nifireg_port}/nifi-registry/"
      fi
      if [[ ${HAS_SCHEMAREGISTRY:-0} == 1 ]]; then
        local schemareg_port=$(service_port $tmp_template_file SCHEMAREGISTRY SCHEMA_REGISTRY_SERVER schema.registry.port schema.registry.ssl.port)
        echo "SR=Schema Registry=${protocol}://{host}:${schemareg_port}/"
      fi
      if [[ ${HAS_SMM:-0} == 1 ]]; then
        local smm_port=$(service_port $tmp_template_file STREAMS_MESSAGING_MANAGER STREAMS_MESSAGING_MANAGER_UI streams.messaging.manager.ui.port)
        echo "SMM=SMM=${protocol}://{host}:${smm_port}/"
      fi
      if [[ ${HAS_HUE:-0} == 1 ]]; then
        local hue_port=$(service_port $tmp_template_file HUE HUE_LOAD_BALANCER listen)
        echo "HUE=Hue=${protocol}://{host}:${hue_port}/"
      fi
      if [[ ${HAS_ATLAS:-0} == 1 ]]; then
        local atlas_port=$(service_port $tmp_template_file ATLAS ATLAS_SERVER atlas_server_http_port atlas_server_https_port)
        echo "ATLAS=Atlas=${protocol}://{host}:${atlas_port}/"
      fi
      if [[ ${HAS_RANGER:-0} == 1 ]]; then
        local ranger_port=$(service_port $tmp_template_file RANGER "" ranger_service_http_port ranger_service_https_port)
        echo "RANGER=Ranger=${protocol}://{host}:${ranger_port}/"
      fi
      if [[ ${HAS_KNOX:-0} == 1 ]]; then
        local knox_port=$(service_port $tmp_template_file KNOX KNOX_GATEWAY gateway_port)
        echo "KNOX=Knox=${protocol}://{host}:${knox_port}/gateway/homepage/home/"
      fi
      if [[ ${HAS_CDSW:-0} == 1 ]]; then
        echo "CDSW=CDSW=${protocol}://cdsw.{ip_address}.nip.io/"
        echo "DATAVIZ=CDP Data Visualization=${protocol}://viz.cdsw.{ip_address}.nip.io/"
      fi
      if [[ ${TF_VAR_pvc_data_services:-false} == "true" ]]; then
        echo "ECS=CDP Private Cloud=https://console-cdp.apps.ecs.{ecs_ip_address}.nip.io/"
      fi
    ) | sort
  ) | tr "\n" "," | sed 's/,$//'
  rm -f $tmp_template_file
}

function clean_all() {
  systemctl stop cloudera-scm-server cloudera-scm-agent cloudera-scm-supervisord kadmin krb5kdc chronyd mosquitto postgresql-${PG_VERSION} httpd shellinaboxd
  service minifi stop; systemctl stop minifi;
  service efm stop; systemctl stop efm;
  pids=$(ps -ef | grep cloudera | grep -v grep | awk '{print $2}')
  if [[ $pids != "" ]]; then
    kill -9 $pids
  fi

  if [[ -d /opt/cloudera/parcels/CDSW/scripts ]]; then
    while true; do /opt/cloudera/parcels/CDSW/scripts/stop-cdsw-app-standalone.sh && break; done
    while true; do /opt/cloudera/parcels/CDSW/scripts/stop-kubelet-standalone.sh && break; done
    while true; do /opt/cloudera/parcels/CDSW/scripts/stop-dockerd-standalone.sh && break; done
  fi

  mounts=$(grep docker /proc/mounts | awk '{print $2}')
  if [[ $mounts != "" ]]; then
    umount $mounts
  fi
  pids=$(grep /dev/mapper/docker /proc/[0-9]*/mountinfo | awk -F/ '{print $3}' | sort -u)
  if [[ $pids != "" ]]; then
    kill -9 $pids
  fi
  while true; do
    for dv in $(dmsetup ls | sort | awk '{print $1}' | grep "docker"); do
      echo "Removing device $dv"
      dmsetup remove "$dv" || true
    done
    [[ $(dmsetup ls | grep "docker" | wc -l) -eq 0 ]] && break
    sleep 1
  done
  lvdisplay docker/thinpool >/dev/null 2>&1 && while true; do lvremove docker/thinpool && break; sleep 1; done
  vgdisplay docker >/dev/null 2>&1 && while true; do vgremove docker && break; sleep 1; done
  pvdisplay $DOCKER_DEVICE >/dev/null 2>&1 && while true; do pvremove $DOCKER_DEVICE && break; sleep 1; done
  dd if=/dev/zero of=$DOCKER_DEVICE bs=1M count=100

  echo "$THE_PWD" | kinit admin
  if [[ ! -z ${LOCAL_HOSTNAME:-} ]]; then
    ipa host-remove-principal $(hostname -f) host/${LOCAL_HOSTNAME}
  fi
  ipa host-del $(hostname -f)
  ipa-client-install --uninstall --unattended

  cp -f /etc/cloudera-scm-agent/config.ini.original /etc/cloudera-scm-agent/config.ini

  rm -rf \
    /var/lib/pgsql/${PG_VERSION}/data/* \
    /var/lib/pgsql/${PG_VERSION}/initdb.log \
    /var/kerberos/krb5kdc/* \
    /var/lib/{accumulo,cdsw,cloudera-host-monitor,cloudera-scm-agent,cloudera-scm-eventserver,cloudera-scm-server,cloudera-service-monitor,cruise_control,druid,flink,hadoop-hdfs,hadoop-httpfs,hadoop-kms,hadoop-mapreduce,hadoop-yarn,hbase,hive,impala,kafka,knox,kudu,livy,nifi,nifiregistry,nifitoolkit,oozie,phoenix,ranger,rangerraz,schemaregistry,shellinabox,solr,solr-infra,spark,sqoop,streams_messaging_manager,streams_replication_manager,superset,yarn-ce,zeppelin,zookeeper}/* \
    /var/log/{atlas,catalogd,cdsw,cloudera-scm-agent,cloudera-scm-alertpublisher,cloudera-scm-eventserver,cloudera-scm-firehose,cloudera-scm-server,cruisecontrol,flink,hadoop-hdfs,hadoop-httpfs,hadoop-mapreduce,hadoop-yarn,hbase,hive,httpd,hue,hue-httpd,impalad,impala-minidumps,kafka,kudu,livy,nifi,nifiregistry,nifi-registry,oozie,schemaregistry,solr-infra,spark,statestore,streams-messaging-manager,yarn,zeppelin,zookeeper}/* \
    /kudu/*/* \
    /dfs/*/* \
    /yarn/* \
    /var/local/kafka/data/* \
    /var/{lib,run}/docker/* \
    /var/run/cloudera-scm-agent/process/*
}

function create_peer_kafka_external_account() {

  # Check if the current version of CM supports Kafka external credentials
  local cat_name=$(curl \
    -k -s \
    -H "Content-Type: application/json" \
    -u admin:"${THE_PWD}" \
    "$(get_cm_base_url)/api/v40/externalAccounts/supportedCategories" | jq -r '.items[] | select(.name == "KAFKA").name')

  if [[ $cat_name != "KAFKA" ]]; then
    return
  fi

  cat > /tmp/kafka_external.json <<EOF
{
  "name" : "cluster_${PEER_CLUSTER_ID}",
  "displayName" : "cluster_${PEER_CLUSTER_ID}",
  "typeName" : "KAFKA_SERVICE",
  "accountConfigs" : {
    "items" : [
      {
        "name" : "kafka_bootstrap_servers",
        "value" : "${PEER_PUBLIC_DNS}:$(get_kafka_port)"
      }, {
        "name" : "kafka_security_protocol",
        "value" : "$(get_kafka_security_protocol)"
      }
$(
  if [[ $(is_kerberos_enabled) == "yes" ]]; then
    cat <<EOF2
      , {
        "name" : "kafka_jaas_secret1",
        "value" : "${THE_PWD}"
      }, {
        "name" : "kafka_jaas_template",
        "value" : "org.apache.kafka.common.security.plain.PlainLoginModule required username=\"admin\" password=\"##JAAS_SECRET_1##\";"
      }, {
        "name" : "kafka_sasl_mechanism",
        "value" : "PLAIN"
      }
EOF2
  fi
)
$(
  if [[ $(is_tls_enabled) == "yes" ]]; then
    cat <<EOF3
      , {
        "name" : "kafka_truststore_password",
        "value" : "${THE_PWD}"
      }, {
        "name" : "kafka_truststore_path",
        "value" : "${TRUSTSTORE_JKS}"
      }, {
        "name" : "kafka_truststore_type",
        "value" : "JKS"
      }
EOF3
  fi
)
    ]
  }
}
EOF

  curl \
    -i -k \
    -X POST \
    -H "Content-Type: application/json" \
    -d @/tmp/kafka_external.json \
    -u admin:"${THE_PWD}" \
    "$(get_cm_base_url)/api/v40/externalAccounts/create"

  rm -f /tmp/kafka_external.json
}

function compare_version() {
  local v1=$1
  local v2=$2
  python -c '
v1 = tuple(map(int, "'"$v1"'".split(".")))
v2 = tuple(map(int, "'"$v2"'".split(".")))
if v1 == v2:
  print("=")
elif v1 < v2:
  print("<")
else:
  print(">")
'
}

function nifi_reporting_task_state() {
  local rt_name=$1
  local state=$2

  if [ "$(is_tls_enabled)" == "yes" ]; then
    scheme=https
    port=8443
  else
    scheme=http
    port=8080
  fi
  local api_url="${scheme}://${CLUSTER_HOST}:${port}/nifi-api"
  while true; do
    set +e
    token=$(curl -s -X POST -d "username=admin&password=${THE_PWD}" -k "${api_url}/access/token")
    RET=$?
    set +e
    if [[ $RET == 0 ]]; then
      break
    fi
    echo "Waiting for NiFi to be ready..."
    sleep 5
  done
  rts="$(curl -s -k -H "Authorization: Bearer $token" "${api_url}/flow/reporting-tasks")"
  rt_id=$(echo "$rts" | jq -r '.reportingTasks[] | . as $r | .component | select(.name == "'"$rt_name"'").id')
  rt_revision=$(echo "$rts" | jq -rc '.reportingTasks[] | . as $r | .component | select(.name == "'"$rt_name"'") | $r.revision')
  curl -s -k -H "Authorization: Bearer $token" "${api_url}/reporting-tasks/${rt_id}/run-status" -d '{"state": "'"$state"'", "revision": '"$rt_revision"'}' -H 'Content-Type: application/json' -X PUT
}

function detect_docker_device() {
  echo "INFO: Docker device was not specified in the command line. Will try to detect a free device to use" >&2
  local tmp_file=/tmp/.device.list
  # Find devices that are not mounted and have size greater than or equal to 200G
  lsblk -o NAME,MOUNTPOINT,SIZE -s -p -n | awk '/^\// && NF == 2 && $NF ~ /([2-9]|[0-9][0-9])[0-9][0-9]G/' > "${tmp_file}"
  if [[ $(cat "${tmp_file}" | wc -l) == 0 ]]; then
    echo "WARNING: Could not find any candidate devices." >&2
  elif [[ $(cat "${tmp_file}" | wc -l) -gt 1 ]]; then
    echo "WARNING: Found more than 1 possible devices to use:" >&2
    cat "${tmp_file}" >&2
  else
    echo "INFO: Found 1 device to use:" >&2
    cat "${tmp_file}" >&2
    awk '{print $1}' "${tmp_file}"
  fi
  rm -f "${tmp_file}"
}

function enable_py3() {
  export MANPATH=
  # On CentOS 7, we use the rh-python38 package, which needs to be activated.
  # On CentOS/RHEL 8, we use the python38 package, which is active by default.
  [[ -f /opt/rh/rh-python38/enable ]] && source /opt/rh/rh-python38/enable
  if [[ $(python -c 'import sys; print(sys.version_info.major)') != "3" ]]; then
    echo "ERROR: Python 3 is not active."
    exit 1
  fi
}

function get_public_ip() {
  local retries=5
  while [[ $retries -gt 0 ]]; do
    local public_ip=$(curl -sL http://ifconfig.me || curl -sL http://api.ipify.org/ || curl -sL https://ipinfo.io/ip)
    if [[ $public_ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
      echo $public_ip
      return
    fi
    sleep 5
    retries=$((retries - 1))
  done
  echo "ERROR: Could not retrieve public IP for this instance. Probably a transient error. Please try again." >&2
  exit 1
}

function deploy_os_prereqs() {
  log_status "Ensuring SElinux is disabled"
  setenforce 0 || true
  if [[ -f /etc/selinux/config ]]; then
    sed -i 's/SELINUX=.*/SELINUX=disabled/' /etc/selinux/config
  fi

  log_status "Ensure domain search list does not contain nip.io"
  fix_resolv_conf

  if [[ $(get_os_type) == "RHEL" ]]; then
    log_status "Disable RHEL Subscription Manager"
    sed -i.bak 's/^ *enabled=.*/enabled=0/' /etc/yum/pluginconf.d/subscription-manager.conf
  fi

  log_status "Installing EPEL repo"
  install_epel

  log_status "Installing base dependencies"
  yum_install vim wget curl git bind-utils figlet cowsay jq rng-tools rsync
  # For troubleshooting purposes, when needed
  yum_install sysstat strace iotop lsof
  # ROCKY8: Allow install on Rocky
  add_rocky_support
}

function deploy_cluster_prereqs() {
  log_status "Installing cluster dependencies"
  # Install Python 3.8
  install_python

  # Install dependencies
  yum_install nodejs gcc-c++ make mosquitto transmission-cli httpd

  # ShellInABox
  if [[ $(get_os_major_version) == "7" ]]; then
    yum_install shellinabox
  else
    # At the time of this edit, there's no package of shellinabox for RHEL/CentOS 8 in EPEL
    yum_install openssl-devel pam-devel zlib-devel autoconf automake libtool
    rm -rf /tmp/shellinabox
    git clone https://github.com/shellinabox/shellinabox.git /tmp/shellinabox
    pushd /tmp/shellinabox
    autoreconf -i
    ./configure --disable-runtime-loading --disable-pam
    sed -E -i 's/(^LIBS.*)/\1-lssl -lcrypto /' Makefile
    sed -E -i '/^\s*debian\// d' Makefile

    make install
    mkdir -p /usr/share/shellinabox
    cp shellinabox/*.css /usr/share/shellinabox/

    useradd -c "Shellinabox" -d /var/lib/shellinabox -s /sbin/nologin -U shellinabox
    cat <<'EOF' > /etc/sysconfig/shellinaboxd
USER=shellinabox
GROUP=shellinabox
CERTDIR=/var/lib/shellinabox
PORT=4200
OPTS="--disable-ssl-menu -s /:LOGIN"
EOF

    cat <<'EOF' > /usr/lib/systemd/system/shellinaboxd.service
[Unit]
Description=Shell In A Box daemon
After=network.target nss-lookup.target
[Service]
EnvironmentFile=-/etc/sysconfig/shellinaboxd
WorkingDirectory=/usr/share/shellinabox
ExecStart=/usr/local/bin/shellinaboxd -u $USER -g $GROUP --cert=${CERTDIR} --port=${PORT} $OPTS
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF

    popd
  fi
  # FIX-ON-GCP: Add missing packages
  yum_install iptables firewalld net-tools krb5-devel

  # Below is needed for secure clusters (required by Impyla)
  yum_install cyrus-sasl-md5 cyrus-sasl-plain cyrus-sasl-gssapi cyrus-sasl-devel
}

function resolve_host_addresses() {
  local prefix=${1:-cdp}
  case "${CLOUD_PROVIDER}" in
    aws)
        sed -i.bak '/server 169.254.169.123/ d' /etc/chrony.conf
        echo "server 169.254.169.123 prefer iburst minpoll 4 maxpoll 4" >> /etc/chrony.conf
        systemctl enable chronyd
        systemctl restart chronyd
        export PRIVATE_DNS=$(curl http://169.254.169.254/latest/meta-data/local-hostname)
        export PRIVATE_IP=$(curl http://169.254.169.254/latest/meta-data/local-ipv4)
        export PUBLIC_DNS=${prefix}.${PUBLIC_IP}.nip.io
        ;;
    azure)
        systemctl enable chronyd
        systemctl restart chronyd
        export PRIVATE_DNS="$(cat /etc/hostname).$(grep search /etc/resolv.conf | awk '{print $2}')"
        export PRIVATE_IP=$(hostname -I | awk '{print $1}')
        export PUBLIC_DNS=${prefix}.${PUBLIC_IP}.nip.io
        # Added to prevent DNS leak to nip.io
        sed -i.bak -e "s/plugins = ifcfg-rh,/dns=none/g" /etc/NetworkManager/NetworkManager.conf 
        systemctl restart NetworkManager
        ;;
    gcp)
        echo "server 169.254.169.254 prefer iburst minpoll 4 maxpoll 4" >> /etc/chrony.conf
        systemctl enable chronyd
        systemctl restart chronyd
        export PRIVATE_DNS=$(curl -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/hostname)
        export PRIVATE_IP=$(curl -s -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/network-interfaces/0/ip)
        export PUBLIC_DNS=${prefix}.${PUBLIC_IP}.nip.io
        ;;
    aliyun)
        export PRIVATE_DNS=$(curl -s http://100.100.100.200/latest/meta-data/hostname)
        [[ "$PRIVATE_DNS" == *"."* ]] || PRIVATE_DNS="${PRIVATE_DNS}.local"
        export PRIVATE_IP=$(curl -s http://100.100.100.200/latest/meta-data/private-ipv4)
        export PUBLIC_DNS=${prefix}.${PRIVATE_IP}.nip.io
        ;;
    generic)
        export PRIVATE_DNS="$(cat /etc/hostname).$(grep search /etc/resolv.conf | awk '{print $2}')"
        export PRIVATE_IP=$(hostname -I | awk '{print $1}')
        export PUBLIC_DNS=${prefix}.${PRIVATE_IP}.nip.io
        ;;
    *)
        export PRIVATE_DNS=$(hostname -f)
        [[ "$PRIVATE_DNS" == *"."* ]] || PRIVATE_DNS="${PRIVATE_DNS}.local"
        export PRIVATE_IP=$(hostname -I | awk '{print $1}')
        export PUBLIC_DNS=$PRIVATE_DNS
  esac

  if [ "$PUBLIC_DNS" == "" ]; then
    echo "ERROR: Could not retrieve public DNS for this instance. Probably a transient error. Please try again."
    exit 1
  fi
  export CLUSTER_HOST=$PUBLIC_DNS
}

function complete_host_initialization() {
  local prefix=${1:-cdp}
  log_status "Setting cluster identity"
  if [[ -f /etc/workshop.conf ]]; then
    cat /etc/workshop.conf >> /etc/profile
  fi

  log_status "Ensuring there's plenty of entropy"
  systemctl enable rngd
  systemctl start rngd

  log_status "Configuring kernel parameters"
  echo never > /sys/kernel/mm/transparent_hugepage/enabled
  echo never > /sys/kernel/mm/transparent_hugepage/defrag
  echo "echo never > /sys/kernel/mm/transparent_hugepage/enabled" >> /etc/rc.d/rc.local
  echo "echo never > /sys/kernel/mm/transparent_hugepage/defrag" >> /etc/rc.d/rc.local
  # add tuned optimization https://www.cloudera.com/documentation/enterprise/latest/topics/cdh_admin_performance.html
  cat >> /etc/sysctl.conf <<EOF
vm.swappiness = 1
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF
  sysctl -p
  timedatectl set-timezone UTC || true

  log_status "Disabling firewalls, if configured"
  systemctl disable firewalld || true
  systemctl stop firewalld || true

  log_status "Enabling password authentication"
  sed -i.bak 's/PasswordAuthentication *no/PasswordAuthentication yes/' /etc/ssh/sshd_config

  log_status "Resetting SSH user password"
  echo "$SSH_PWD" | sudo passwd --stdin "$SSH_USER"

  log_status "Handling cloud provider specific settings"
  resolve_host_addresses "$prefix"

  log_status "Setting up /etc/hosts"
  # Public DNS must come first"
  sed -i.bak "/^${PRIVATE_IP}/d;/^::1/d" /etc/hosts
  echo "$PRIVATE_IP $PUBLIC_DNS $PRIVATE_DNS" >> /etc/hosts
  if [[ ! -z ${IPA_HOST:-} ]]; then
    sed -i.bak "/${IPA_HOST}/d" /etc/hosts
    if [[ ! -z ${IPA_PRIVATE_IP:-} ]]; then
      echo "$IPA_PRIVATE_IP $IPA_HOST" >> /etc/hosts
    fi
  fi
  if [[ ! -z ${ECS_PUBLIC_DNS:-} ]]; then
    sed -i.bak "/${ECS_PUBLIC_DNS}/d" /etc/hosts
    if [[ ! -z ${ECS_PRIVATE_IP:-} ]]; then
      echo "$ECS_PRIVATE_IP $ECS_PUBLIC_DNS" >> /etc/hosts
    fi
  fi

  log_status "Setting domain name"
  sed -i.bak '/kernel.domainname/d' /etc/sysctl.conf
  echo "kernel.domainname=${PUBLIC_DNS#*.}" >> /etc/sysctl.conf
  sysctl -p

  log_status "Configuring networking"
  hostnamectl set-hostname $CLUSTER_HOST
  if [[ -f /etc/sysconfig/network ]]; then
    sed -i "/HOSTNAME=/ d" /etc/sysconfig/network
  fi
  echo "HOSTNAME=${CLUSTER_HOST}" >> /etc/sysconfig/network
  export HOSTNAME=${CLUSTER_HOST}

}

function fix_resolv_conf() {
  if [[ $(systemctl list-unit-files | grep -c ^NetworkManager.service) -gt 0 ]]; then
    mkdir -p /etc/NetworkManager/conf.d
    echo -e "[main]\ndns=none" > /etc/NetworkManager/conf.d/90-dns-none.conf # Prevent NM attempts to restore resolv.conf
    systemctl reload NetworkManager
  fi
  chattr -i /etc/resolv.conf
  sed -i 's/[^ ]*nip.io//g' /etc/resolv.conf
  chattr +i /etc/resolv.conf # Ensure nothing else modify resolv.conf
}

function download_parcels() {
  mkdir -p /opt/cloudera/parcel-repo
  mkdir -p /opt/cloudera/parcels
  # We want to execute ln -s within the parcels directory for preloading
  pushd "/opt/cloudera/parcels"
  while [ $# -gt 0 ]; do
    component=$1
    version=$2
    url=$3
    shift 3
    echo ">>> $component - $version - $url"
    # Download parcel manifest
    manifest_url="$(check_for_presigned_url "${url%%/}/manifest.json")"
    paywall_curl "$manifest_url" "/tmp/manifest.json"
    # Find the parcel name for the specific component and version
    parcel_name=$(jq -r '.parcels[] | select(.parcelName | contains("'"$version"'-el'"$(get_os_major_version)"'.parcel")) | select(.components[] | .name == "'"$component"'").parcelName' /tmp/manifest.json)
    # Create the hash file
    hash=$(jq -r '.parcels[] | select(.parcelName | contains("'"$version"'-el'"$(get_os_major_version)"'.parcel")) | select(.components[] | .name == "'"$component"'").hash' /tmp/manifest.json)
    echo "$hash" > "/opt/cloudera/parcel-repo/${parcel_name}.sha"
    if [[ ! -f "/opt/cloudera/parcel-repo/${parcel_name}" || $(sha1sum "/opt/cloudera/parcel-repo/${parcel_name}" 2> /dev/null || true) != "$hash" ]]; then
      # Download the parcel file - in the background
      parcel_url="$(check_for_presigned_url "${url%%/}/${parcel_name}")"
      paywall_wget "${parcel_url}" "/opt/cloudera/parcel-repo/${parcel_name}" &
    fi
  done
  wait
  # Create the torrent file for the parcel
  for parcel_file in /opt/cloudera/parcel-repo/*.parcel; do
    transmission-create -s 512 -o "${parcel_file}.torrent" "${parcel_file}" &
  done
  wait
}

function distribute_parcels() {
  # Predistribute parcel
  for parcel_file in /opt/cloudera/parcel-repo/*.parcel; do
    tar zxf "$parcel_file" -C "/opt/cloudera/parcels" &
  done
  wait
  log_status "Pre-activating parcels"
  for parcel_file in /opt/cloudera/parcel-repo/*.parcel; do
    parcel_name="$(basename "$parcel_file")"
    product_name="${parcel_name%%-*}"
    rm -f "${product_name}"
    ln -s "${parcel_name%-*.parcel}" "${product_name}"
    touch "/opt/cloudera/parcels/${product_name}/.dont_delete"
  done
  popd
}

function install_csds() {
  while [ $# -gt 0 ]; do
    url=$1
    shift
    echo "---- Downloading $url"
    file_name=$(basename "${url%%\?*}")
    if [ "$(get_remote_repo_username)" != "" -a "$(get_remote_repo_password)" != "" ]; then
      auth="--user '$(get_remote_repo_username)' --password '$(get_remote_repo_password)'"
    else
      auth=""
    fi
    paywall_wget "$url" "/opt/cloudera/csd/${file_name}"
    # Patch CDSW CSD so that we can use it on CDP
    if [ "${HAS_CDSW:-1}" == "1" -a "$url" == "$CDSW_CSD_URL" -a "$CM_MAJOR_VERSION" == "7" ]; then
      jar xvf /opt/cloudera/csd/CLOUDERA_DATA_SCIENCE_WORKBENCH-*.jar descriptor/service.sdl
      sed -i 's/"max" *: *"6"/"max" : "7"/g' descriptor/service.sdl
      jar uvf /opt/cloudera/csd/CLOUDERA_DATA_SCIENCE_WORKBENCH-*.jar descriptor/service.sdl
      rm -rf descriptor
    fi
    # TODO: Remove patch below when no longer needed
    # Patch SSB CSD due to CSA-3630 and CSA-3750
    if [[ -f /opt/cloudera/csd/SQL_STREAM_BUILDER-1.14.0-csa1.7.0.1-cdh7.1.7.0-551-29340707.jar ]]; then
      rm -rf /tmp/ssb_csd
      mkdir -p /tmp/ssb_csd
      pushd /tmp/ssb_csd
      jar xvf /opt/cloudera/csd/SQL_STREAM_BUILDER-1.14.0-csa1.7.0.1-cdh7.1.7.0-551-29340707.jar
      sed -i \
's#${CONF_DIR}/cm-auto-host_cert_chain.pem#/opt/cloudera/security/x509/host.pem#;'\
's#${CONF_DIR}/cm-auto-host_key.pem#/opt/cloudera/security/x509/key.pem#;'\
's#${CONF_DIR}/cm-auto-host_key.pw#/opt/cloudera/security/x509/pwfile#;'\
's#${NGINX_CONF_DIR}/logs/error.log#/var/log/ssb/load_balancer-error.log#;'\
's#${NGINX_CONF_DIR}/logs/access.log#/var/log/ssb/load_balancer-access.log#' ./scripts/set-dependencies.sh
      jar cvf /opt/cloudera/csd/SQL_STREAM_BUILDER-1.14.0-csa1.7.0.1-cdh7.1.7.0-551-29340707.jar *
      chown cloudera-scm:cloudera-scm /opt/cloudera/csd/SQL_STREAM_BUILDER-1.14.0-csa1.7.0.1-cdh7.1.7.0-551-29340707.jar
      popd
      rm -rf /tmp/ssb_csd
    fi
  done
}

function paywall_wget() {
  local url=$1
  local output=$2

  # Only use authentication if source is not a S3 bucket
  local auth=""
  if [[ $url != *"s3.amazonaws.com"* ]]; then
    auth=$WGET_BASIC_AUTH
  fi
  retry_if_needed 5 5 "wget --continue --progress=dot:giga $auth '${url}' -O '${output}'"
}

function paywall_curl() {
  local url=$1
  local output=$2

  # Only use authentication if source is not a S3 bucket
  local auth=""
  if [[ $url != *"s3.amazonaws.com"* ]]; then
    auth=$CURL_BASIC_AUTH
  fi
  retry_if_needed 5 5 "curl $auth --silent '${url}' > '${output}'"
}

function install_ecs() {
  log_status "Copy CM repo file to ECS host"
  scp -o StrictHostKeyChecking=no -i /home/${SSH_USER}/.ssh/${NAMESPACE}.pem $CM_REPO_FILE ${SSH_USER}@${ECS_PRIVATE_IP}:/tmp/cm.repo
  log_status "Copy agent config file to ECS host"
  scp -o StrictHostKeyChecking=no -i /home/${SSH_USER}/.ssh/${NAMESPACE}.pem /etc/cloudera-scm-agent/config.ini ${SSH_USER}@${ECS_PRIVATE_IP}:/tmp/scm-agent-config.ini
  log_status "Run agent install on ECS host"
  ssh -tt -o StrictHostKeyChecking=no -i /home/${SSH_USER}/.ssh/${NAMESPACE}.pem ${SSH_USER}@${ECS_PRIVATE_IP} "sudo mv /tmp/cm.repo $CM_REPO_FILE; sudo chown root:root $CM_REPO_FILE; sudo bash -x /tmp/resources/setup-ecs.sh install-cloudera-agent $CLUSTER_HOST $PRIVATE_IP /tmp/scm-agent-config.ini > /tmp/resources/setup-ecs.install-cloudera-agent.log 2>&1"

  CURL=(curl -s -u "admin:${THE_PWD}" -H "accept: application/json" -H "Content-Type: application/json")

  log_status "Wait for ECS host heartbeat"
  ECS_CLUSTER_NAME=OneNodeECS
  while [[ -z ${ECS_HOST_ID:-} ]]; do
    ECS_HOST_ID=$("${CURL[@]}" -X GET "https://${CLUSTER_HOST}:7183/api/v32/hosts" -H "accept: application/json" -H "Content-Type: application/json" | jq -r '.items[] | select(.hostname == "'"$ECS_PUBLIC_DNS"'").hostId')
  done

  log_status "Upload license"
  curl -s -u "admin:${THE_PWD}" \
    -H "accept: application/json" -H 'Content-Type: multipart/form-data' \
    "https://${CLUSTER_HOST}:7183/api/v40/cm/license" \
    -F license=@${LICENSE_FILE_PATH}

  log_status "Add CDP-PVC parcel repo and paywall credentials to CM"
  REPOS=$("${CURL[@]}" -X GET "https://${CLUSTER_HOST}:7183/api/v44/cm/config" | jq -r '.items[] | select(.name == "REMOTE_PARCEL_REPO_URLS").value')
  REPOS="$(echo "$REPOS" | sed "s#${ECS_PARCEL_REPO}##g;s#,,#,#g;s/,$//"),${ECS_PARCEL_REPO}"
  "${CURL[@]}" -X PUT "https://${CLUSTER_HOST}:7183/api/v44/cm/config" -d '{"items":[{"name":"REMOTE_PARCEL_REPO_URLS", "value":"'"$REPOS"'"}, {"name":"REMOTE_REPO_OVERRIDE_USER", "value":"'"$(get_remote_repo_username)"'"}, {"name":"REMOTE_REPO_OVERRIDE_PASSWORD", "value":"'"$(get_remote_repo_password)"'"}]}'
  "${CURL[@]}" -X POST "https://${CLUSTER_HOST}:7183/api/v44/cm/commands/refreshParcelRepos"
  sleep 10

  log_status "Add ECS cluster"
  "${CURL[@]}" -X POST \
    "https://${CLUSTER_HOST}:7183/api/v51/clusters" \
    -d '{"items":[{"name":"'"${ECS_CLUSTER_NAME}"'","displayName":"'"${ECS_CLUSTER_NAME}"'","fullVersion":"'"${ECS_BUILD}"'","clusterType":"EXPERIENCE_CLUSTER"}]}'

  log_status "Add host to ECS cluster"
  "${CURL[@]}" -X POST \
    "https://${CLUSTER_HOST}:7183/api/v51/clusters/${ECS_CLUSTER_NAME}/hosts" \
    -d '{"items":[{"hostId":"'"${ECS_HOST_ID}"'","hostname":"'"${ECS_PUBLIC_DNS}"'"}]}'

  log_status "Download, distribute and activate ECS parcel"
  "${CURL[@]}" -X POST \
    "https://${CLUSTER_HOST}:7183/api/v51/clusters/${ECS_CLUSTER_NAME}/parcels/products/ECS/versions/${ECS_BUILD}/commands/startDownload"
  wait_for_parcel_state $ECS_CLUSTER_NAME ECS $ECS_BUILD AVAILABLE_REMOTELY DOWNLOADING DOWNLOADED
  "${CURL[@]}" -X POST \
    "https://${CLUSTER_HOST}:7183/api/v51/clusters/${ECS_CLUSTER_NAME}/parcels/products/ECS/versions/${ECS_BUILD}/commands/startDistribution"
  wait_for_parcel_state $ECS_CLUSTER_NAME ECS $ECS_BUILD DOWNLOADED DISTRIBUTING DISTRIBUTED
  "${CURL[@]}" -X POST \
    "https://${CLUSTER_HOST}:7183/api/v51/clusters/${ECS_CLUSTER_NAME}/parcels/products/ECS/versions/${ECS_BUILD}/commands/activate"
  wait_for_parcel_state $ECS_CLUSTER_NAME ECS $ECS_BUILD DISTRIBUTED ACTIVATING ACTIVATED

  # HAS_ECS: ECS SSL certificate signed by IPA needs to be on CM for provisioning
  log_status "Prepare CM host for ECS certificates"
  mkdir -p ${SEC_BASE}/ecs
  ssh -tt -o StrictHostKeyChecking=no -i /home/${SSH_USER}/.ssh/${NAMESPACE}.pem ${SSH_USER}@${ECS_PRIVATE_IP} "sudo cp ${UNENCRYTED_KEY_PEM} ${HOST_PEM} /home/${SSH_USER}/.; sudo chown ${SSH_USER}:${SSH_USER} /home/${SSH_USER}/unencrypted-key.pem /home/${SSH_USER}/host.pem"
  scp -o StrictHostKeyChecking=no -i /home/${SSH_USER}/.ssh/${NAMESPACE}.pem ${SSH_USER}@${ECS_PRIVATE_IP}:/home/${SSH_USER}/unencrypted-key.pem ${SEC_BASE}/ecs/unencrypted-key.pem 
  scp -o StrictHostKeyChecking=no -i /home/${SSH_USER}/.ssh/${NAMESPACE}.pem ${SSH_USER}@${ECS_PRIVATE_IP}:/home/${SSH_USER}/host.pem ${SEC_BASE}/ecs/host.pem
  chown -R cloudera-scm:cloudera-scm ${SEC_BASE}/ecs

  log_status "Add ECS and Docker services to ECS cluster"
  local svc_json_file=${BASE_DIR}/ecs_svc.json
  cat > $svc_json_file <<EOF
{
  "items": [
    {
      "name": "docker",
      "type": "DOCKER",
      "config": {
        "items": [
          {
            "name": "defaultDataPath",
            "value": "/docker"
          }
        ]
      },
      "roles": [
        {
          "type": "DOCKER_SERVER",
          "hostRef": {
            "hostId": "${ECS_HOST_ID}",
            "hostname": "${ECS_PUBLIC_DNS}"
          },
          "config": {},
          "roleConfigGroupRef": {
            "roleConfigGroupName": "docker-DOCKER_SERVER-BASE"
          }
        }
      ],
      "roleConfigGroups": [
        {
          "name": "docker-DOCKER_SERVER-BASE",
          "roleType": "DOCKER_SERVER",
          "base": true,
          "config": {}
        }
      ]
    },
    {
      "name": "ecs",
      "type": "ECS",
      "config": {
        "items": [
          {
            "name": "app_domain",
            "value": "${ECS_PUBLIC_DNS}"
          },
          {
            "name" : "docker",
            "value" : "docker"
          },
          {
            "name": "cp_prometheus_ingress_user",
            "value": "cloudera-manager"
          },
          {
            "name": "infra_prometheus_ingress_user",
            "value": "cloudera-manager"
          },
          {
            "name": "cp_prometheus_ingress_password",
            "value": "${THE_PWD}"
          },
          {
            "name": "external_registry_enabled",
            "value": "true"
          },
          {
            "name": "infra_prometheus_ingress_password",
            "value": "${THE_PWD}"
          },
          {
            "name": "defaultDataPath",
            "value": "/ecs/longhorn-storage"
          },
          {
            "name": "lsoDataPath",
            "value": "/ecs/local-storage",
            "sensitive": false
          },
          {
            "name": "target_redundancy",
            "value": 1
          },
          {
            "name": "longhorn_replication",
            "value": 1
          },
          {
            "name": "internal_mirror",
            "value": "true"
          },
          {
            "name": "cluster_cidr",
            "value": "172.42.0.0/16"
          },
          {
            "name": "service_cidr",
            "value": "172.43.0.0/16"
          },
          {
            "name": "ssl_certificate",
            "value": "${SEC_BASE}/ecs/host.pem"
          },
          {
            "name": "ssl_private_key",
            "value": "${SEC_BASE}/ecs/unencrypted-key.pem"
          }
        ]
      },
      "roles": [
        {
          "type": "ECS_SERVER",
          "hostRef": {
            "hostId": "${ECS_HOST_ID}",
            "hostname": "${ECS_PUBLIC_DNS}"
          },
          "config": {},
          "roleConfigGroupRef": {
            "roleConfigGroupName": "ecs-ECS_SERVER-BASE"
          }
        }
      ],
      "roleConfigGroups": [
        {
          "name": "ecs-ECS_SERVER-BASE",
          "roleType": "ECS_SERVER",
          "base": true,
          "config": {}
        }
      ]
    }
  ]
}
EOF
  "${CURL[@]}" -X POST \
    "https://${CLUSTER_HOST}:7183/api/v51/clusters/${ECS_CLUSTER_NAME}/services" \
    -d @$svc_json_file

  log_status "Initialize ECS"
  # HAS_ECS: using values.yaml to configure ECS components
  local values_yaml_file=${BASE_DIR}/values.yaml
  cat > $values_yaml_file <<EOF
ContainerInfo:
  Mode: public
  CopyDocker: false

Database:
  Mode: embedded
  EmbeddedDbStorage: 20

Vault:
  Mode: embedded
  EmbeddedStorage: 20
EOF

  local values_yaml=$(sed ':a;N;$!ba;s/\n/\\n/g' "$values_yaml_file" | sed 's/"/\\"/g')
  local ecs_json_file=${BASE_DIR}/ecs_install.json
  cat > $ecs_json_file <<EOF
{
  "remoteRepoUrl": "${ECS_REPO}",
  "valuesYaml": "${values_yaml}",
  "containerizedClusterName": "${ECS_CLUSTER_NAME}",
  "experienceClusterName": "${ECS_CLUSTER_NAME}",
  "datalakeClusterName": "OneNodeCluster"
}
EOF

  local ecs_call_log=/tmp/ecs-call.$(date +%s).log
  "${CURL[@]}" -X POST \
    -H "Referer: https://${CLUSTER_HOST}:7183/cmf/express-wizard/wizard?allowResume=false&clusterType=EXPERIENCE_CLUSTER" \
    "https://${CLUSTER_HOST}:7183/api/v44/controlPlanes/commands/installEmbeddedControlPlane" \
    -d @$ecs_json_file | tee $ecs_call_log
  local job_id=$(jq '.id' $ecs_call_log)

  while true; do
    [[ $(curl -s -k --location-trusted -u admin:"${THE_PWD}" "$(get_cm_base_url)/api/v19/commands/$job_id" | jq -r '.active') == "false" ]] && break
    echo "Waiting for ECS setup to finish"
    sleep 1
  done
  # HAS_ECS: Check ECS setup status after Job has finished 
  if [[ $(curl -s -k --location-trusted -u admin:"${THE_PWD}" "$(get_cm_base_url)/api/v19/commands/$job_id" | jq -r '.success') == "false" ]]; then
    echo "ERROR: ECS setup has failed"
    return 1
  else
    echo "ECS setup has been successful"
  fi
}

function wait_for_parcel_state() {
  local cluster_name=$1
  local product=$2
  local build=$3
  local initial_state=$4
  local running_state=$5
  local final_state=$6
  local stage=$initial_state
  while [[ $stage == "$initial_state" || $stage == "$running_state" ]]; do
    stage=$("${CURL[@]}" -X GET "https://${CLUSTER_HOST}:7183/api/v51/clusters/${cluster_name}/parcels/products/${product}/versions/${build}" | jq -r '.stage')
    echo "$(date) - $stage"
    sleep 1
  done
  if [[ $stage != "$final_state" ]]; then
    echo "ERROR: Failed to process parcel $product $build. Current state: $stage"
    return 1
  fi
}

function set_java_alternatives() {
  local java_home=${1:-$(ls -1d /usr/java/*-cloudera 2>/dev/null| sort | tail -1 || true)}
  local priority=${2:-9999999}

  if [[ -n $java_home && -d $java_home ]]; then
    java_home=$(readlink -f ${java_home})
    local link_dir=/usr/bin
    local jre_bin_dir
    local jdk_bin_dir
    jdk_bin_dir=$(readlink -f "${java_home}/bin")
    jre_bin_dir=$(readlink -f "${java_home}/jre/bin" || true)

    local bin_dirs=()
    for bin_dir in $jre_bin_dir $jdk_bin_dir; do
      if [[ -d $bin_dir ]]; then
        bin_dirs+=("$bin_dir")
      fi
    done
    java_path=$(find "${bin_dirs[@]}" -name java | head -1)
    local cmd=(sudo alternatives --install "$link_dir/java" java "$java_path" "${priority}")

    local names="|java|"
    for path in $(find "${bin_dirs[@]}" ! -type d -perm -001 | sort); do
      name=$(basename "$path")
      [[ $names == *"|$name|"* ]] && continue
      cmd+=(--slave "$link_dir/$name" "$name" "$path")
    done

    "${cmd[@]}"

    sudo alternatives --install "${JDK_BASE}/jre-openjdk" jre_openjdk "${java_home}" 9999999
  fi
}

function install_java() {
  if [[ -n ${JAVA_PACKAGE_NAME:-} ]]; then
    yum_install "${JAVA_PACKAGE_NAME}"
    if ! javac; then
      set_java_alternatives
    fi
  fi
  if [[ -n ${OPENJDK_VERSION:-} ]]; then
    local major_version=${OPENJDK_VERSION%%.*}
    if [[ $major_version -ne 11 && $major_version -ne 17 ]]; then
      echo "ERROR: Only OpenJDK versions 11.x and 17.x can be installed through the property OPENJDK_VERSION."
      echo "ERROR: The version specified was ${OPENJDK_VERSION}."
      echo "ERROR: For other versions, find an available package for CentOS and use the JAVA_PACKAGE_NAME property."
      exit 1
    fi
    local tmp_tarball="/tmp/openjdk.tar.gz"
    local openjdk_url
    openjdk_url=$(curl -sL "$OPENJDK_ARCHIVE" | grep -o 'http[^"]*openjdk-'"${OPENJDK_VERSION}"'_linux-x64[^"]*bin.tar.gz' | head -1 || true)
    if [[ -z ${openjdk_url:-} ]]; then
      echo "ERROR: The OpenJDK version ${OPENJDK_VERSION} could not be found in ${OPENJDK_ARCHIVE}."
      echo "ERROR: Choose an option available in the archive and try again."
      exit 1
    fi
    retry_if_needed 5 5 "wget --progress=dot:giga '$openjdk_url' -O '$tmp_tarball'"
    local java_home="${JDK_BASE}/jdk-${major_version}"
    mkdir -p "$java_home"
    tar -C "$java_home" --strip-components=1 -xvf "$tmp_tarball"
    rm -f $tmp_tarball
    if [[ -z ${JAVA_PACKAGE_NAME:-} ]]; then
      set_java_alternatives "$java_home"
    else
      # BIGTOP_JAVA_MAJOR defines which Java version will be used by CDH services.
      # Some services, like CSA, still don't support Java 17. So, if OpenJDK 17 is installed and the OS-packaged
      # Java is present, set BIGTOP_JAVA_MAJOR to the major version of the latter to avoid problems
      if [[ $major_version -ne 17 ]]; then
        bigtop_java_major_version=$major_version
      else
        bigtop_java_major_version=$(java -version 2>&1 | awk -F\" '/version/ {split($2, n, "."); print n[1]}')
      fi
      echo "BIGTOP_JAVA_MAJOR=$bigtop_java_major_version" > /etc/profile.d/cdp.sh
    fi
  fi

  # Sets JAVA_HOME
  local javac_path="$(readlink -f "$(which javac)")"
  export JAVA_HOME="${javac_path%/bin/javac}"
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

function install_epel() {
  yum erase -y epel-release || true; rm -f /etc/yum.repos.r/epel* || true
  if [[ $(get_os_major_version) == "8" ]]; then
    if [[ $(get_os_type) == "CENTOS" ]]; then
      patch_yum_repos_for_centos
      dnf config-manager --set-enabled powertools
      dnf -y install epel-release epel-next-release
    else
      dnf -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm
    fi
  else
    patch_yum_repos_for_centos
    yum_install epel-release
  fi
  yum clean all
  rm -rf /var/cache/yum/
  # Load and accept GPG keys
  yum makecache -y || true
  yum repolist
}

function patch_yum_repos_for_centos() {
  # In July 2024 Centos 7 reached EoL and the repo was moved to the CentOS Vault.
  # The mirrorlist.centos.org host was also decommissioned.
  # The commands below update YUM repo file accordingly, if needed
  if [[ $(get_os_type) == "CENTOS" ]]; then
    sed -i 's/mirror.centos.org/vault.centos.org/g' /etc/yum.repos.d/*.repo
    sed -i 's/^#.*baseurl=http/baseurl=http/g' /etc/yum.repos.d/*.repo
    sed -i 's/^mirrorlist=http/#mirrorlist=http/g' /etc/yum.repos.d/*.repo
    # sed -i 's/metalink=/#metalink=/' /etc/yum.repos.d/*.repo
  fi
}

function install_pg_repo() {
  if [[ $(rpm -qa | grep pgdg-redhat-repo- | wc -l) -eq 0 ]]; then
    if [[ $(get_os_major_version) -eq 7 ]]; then
      yum_install "https://download.postgresql.org/pub/repos/yum/reporpms/EL-7-x86_64/pgdg-redhat-repo-latest.noarch.rpm"
    else
      # Ref: https://www.postgresql.org/download/linux/redhat/
      sudo dnf install -y https://download.postgresql.org/pub/repos/yum/reporpms/EL-8-x86_64/pgdg-redhat-repo-latest.noarch.rpm
      sudo dnf -qy module disable postgresql
    fi
  fi
}

function install_python() {
  if [[ $(get_os_major_version) == "7" ]]; then
    yum_install centos-release-scl
    patch_yum_repos_for_centos
    yum_install rh-python38 rh-python38-python-devel
    alternatives --install /usr/bin/python3 workshop-py3-38 /opt/rh/rh-python38/root/usr/bin/python3.8 99999999 \
      --slave /usr/local/bin/python3 workshop-local-py3-3 /opt/rh/rh-python38/root/usr/bin/python3.8 \
      --slave /usr/local/bin/python3.8 workshop-local-py3-38 /opt/rh/rh-python38/root/usr/bin/python3.8
    /usr/bin/python3 -m pip install --quiet --upgrade pip virtualenv
    enable_py3
  else
    yum_install python38 python38-devel
    alternatives --set python /usr/bin/python3
    alternatives --install /usr/bin/pip pip /usr/bin/pip3 1
  fi
  pip install --quiet --upgrade pip
}

# HAS_ECS: ECS cluster prereqs
function deploy_ecs_prereqs() {
  log_status "Installing ECS dependencies"
  # Install dependencies on python38 for ECS 1.5.x
  install_python
  pip install pyyaml
  yum_install iptables firewalld net-tools make
}

function map_ipa_users() {
  log_status "Configure LDAP/PAM Groups on CDP-BASE"
  CURL=(curl -s -u "admin:${THE_PWD}" -H "accept: application/json" -H "Content-Type: application/json")
  "${CURL[@]}" -X POST \
    "https://${CLUSTER_HOST}:7183/api/v30/externalUserMappings" \
    -d '{"items":[{"name":"cdp-admins","type":"LDAP","authRoles":[{"name":"ROLE_ADMIN"}]},{"name":"cdp-users","type":"LDAP","authRoles":[{"name":"ROLE_CLUSTER_ADMIN"}]}]}'

  log_status "Patch gen_credentials_ipa.sh for IPA support to ECS"
  # Preparing the script before provisioning ECS
  local ipa_patch_file=/tmp/ipa_patch_file.$$
  cat > $ipa_patch_file <<EOF
  # ipa host-add patch for k8s
  if [[ \$HOST =~ \. ]]; then
    ipa host-add \$HOST  --force --no-reverse
  else
    ipa host-add \$HOST.cloudera.com  --force --no-reverse
  fi
EOF
  local search_string='  ipa host-add $HOST --force --no-reverse'
  sed -i.bak -e '/'"$search_string"'/r '"$ipa_patch_file"'' -e '/'"$search_string"'/d' /opt/cloudera/cm/bin/gen_credentials_ipa.sh
}

# ADD-CML: Workspace provisioner
function install_cml() {
  
  local ENDPOINT_HOST="${1}"
  local EXTERNAL_NFS=${2:-0}
  local KUBE_CONFIG="${3:-}"
  local KUBE_DOMAIN="${4:-}"

  log_status "Install CML on $ENDPOINT_HOST"

  local ECS_BASE_URL="https://console-cdp.apps.$ENDPOINT_HOST"
  local ROOT_CA=/opt/cloudera/security/x509/truststore.pem
  local COOKIE_FILE=${BASE_DIR}/cookie.txt.$$
  local LDAP_JSON=${BASE_DIR}/ldap.json.$$
  local VALIDATE_JSON=${BASE_DIR}/validate.json.$$
  local ECS_ENV_JSON=${BASE_DIR}/env.json.$$
  local ECS_CML_JSON=${BASE_DIR}/cml.json.$$

  CURL_POST=(curl -k -X POST -b $COOKIE_FILE -H "Content-Type: application/json")

  log_status "Configure LDAP and groups on ECS-CP"
  local CDP_ACCOUNT_ID=$(curl -v -k --retry 3 $ECS_BASE_URL/authenticate/login/local 2>&1 | grep "location:" | sed 's/.*accountId=//;s/&.*//')
  # Get a session token
  curl -k -X POST -c $COOKIE_FILE -d "username=admin&password=admin" "$ECS_BASE_URL/authenticate/callback/local?accountId=$CDP_ACCOUNT_ID&state=$ECS_BASE_URL" >/dev/null 2>&1
  # Get Admin CRN
  local ADMIN_CRN=$("${CURL_POST[@]}" -d '{}' $ECS_BASE_URL/api/v1/iam/getUser 2>/dev/null | jq -r '.user.crn')
  # Get LDAP
  "${CURL_POST[@]}" -d '{"ldapProviderName": "cm-ldap"}' -o $LDAP_JSON $ECS_BASE_URL/api/v1/iam/describeLdapProvider >/dev/null 2>&1
  # Add Groups (cdp-admins,cdp-users)
  local CDP_ADMINS_CRN=$("${CURL_POST[@]}" -d '{"groupName": "cdp-admins", "syncMembershipOnUserLogin": true}' $ECS_BASE_URL/api/v1/iam/createGroup 2>/dev/null | jq -r '.group.crn')
  local CDP_USERS_CRN=$("${CURL_POST[@]}" -d '{"groupName": "cdp-users", "syncMembershipOnUserLogin": true}' $ECS_BASE_URL/api/v1/iam/createGroup 2>/dev/null | jq -r '.group.crn')
  # Add user "admin" to cdp-admins group
  cat > $ECS_ENV_JSON <<EOF
{
    "groupName": "$CDP_ADMINS_CRN",
    "userId": "$ADMIN_CRN"
}
EOF
  "${CURL_POST[@]}" -d @$ECS_ENV_JSON $ECS_BASE_URL/api/v1/iam/addUserToGroup >/dev/null 2>&1
  # Assign PowerUser Role to cdp-admins
  "${CURL_POST[@]}" -d '{"role": "crn:altus:iam:us-west-1:altus:role:PowerUser", "groupName": "cdp-admins"}' $ECS_BASE_URL/api/v1/iam/assignGroupRole >/dev/null 2>&1
  # Assign Data Catalog Role to cdp-users
  "${CURL_POST[@]}" -d '{"role": "crn:altus:iam:us-west-1:altus:role:DataCatalogCspRuleViewer", "groupName": "cdp-users"}' $ECS_BASE_URL/api/v1/iam/assignGroupRole >/dev/null 2>&1

  # Get JSON values
  local LDAP_url=$(jq -r '.ldapProvider.ldapDetails.url' $LDAP_JSON)
  local LDAP_userSearchBase=$(jq -r '.ldapProvider.ldapDetails.userSearchBase' $LDAP_JSON)
  local LDAP_userSearchFilter=$(jq -r '.ldapProvider.ldapDetails.userSearchFilter' $LDAP_JSON)
  local LDAP_groupSearchBase=$(jq -r '.ldapProvider.ldapDetails.groupSearchBase' $LDAP_JSON)
  local LDAP_groupSearchFilter=$(jq -r '.ldapProvider.ldapDetails.groupSearchFilter' $LDAP_JSON)
  local LDAP_emailMappingAttribute=$(jq -r '.ldapProvider.ldapDetails.emailMappingAttribute' $LDAP_JSON)
  local LDAP_bindDn=$(jq -r '.ldapProvider.ldapDetails.bindDn' $LDAP_JSON)
  local LDAP_tlsCaCertificates="$(cat $ROOT_CA | awk '{printf "%s\\n", $0}')"
  # Build request JSON
  cat > $VALIDATE_JSON <<EOF
{
  "ldapProviderName": "cm-ldap",
  "skipGroupSyncOnLogin": false,
  "url": "$LDAP_url",
  "userSearchBase": "$LDAP_userSearchBase",
  "userSearchFilter": "$LDAP_userSearchFilter",
  "groupSearchBase": "$LDAP_groupSearchBase",
  "groupSearchFilter": "$LDAP_groupSearchFilter",
  "syncGroupsOnLogin": true,
  "emailMappingAttribute": "$LDAP_emailMappingAttribute",
  "showAdvanced": false,
  "bindDn": "$LDAP_bindDn",
  "bindPassword": "",
  "tlsCaCertificates": [
    "$LDAP_tlsCaCertificates"
  ]
}
EOF

  # Handle LDAP Certificate validation
  local return_code=400
  if jq -e . $VALIDATE_JSON  >/dev/null 2>&1 ; then
    # Validate LDAP Config
    return_code=$("${CURL_POST[@]}" -d @$VALIDATE_JSON $ECS_BASE_URL/api/v1/consoleauthenticationcdp/validateLdapConfig 2>/dev/null | jq -r '.code')
    if [ $return_code == "200" ]; then
      "${CURL_POST[@]}" -d @$VALIDATE_JSON $ECS_BASE_URL/api/v1/iam/updateLdapProvider 2>/dev/null
      echo "LDAP is configured with IPA Root CA SSL certificate"
    else
      echo "ERROR: Can't validate LDAP Config, abort"
      return 1
    fi
  else
    echo "ERROR: Invalid LDAP Config, abort"
    return 1
  fi

  # Remove ecs environemnt created by express wizard
  log_status "Rebuild default environment on ECS-CP"
  "${CURL_POST[@]}" -d '{"envNameOrCrn": "ecs"}' $ECS_BASE_URL/api/v1/compute/deregisterClusters >/dev/null 2>&1
  "${CURL_POST[@]}" -d '{"environmentName": "ecs","cascading": true}' $ECS_BASE_URL/api/v1/environments2/deleteEnvironment >/dev/null 2>&1

  # Build request JSON
  cat > $ECS_ENV_JSON <<EOF
{
    "environmentName": "default",
    "address": "https://$CLUSTER_HOST:7183",
    "user": "admin",
    "authenticationToken": "$THE_PWD",
    "clusterNames": [
        "OneNodeCluster"
    ],
    "kubeConfig": "$KUBE_CONFIG",
    "authenticationTokenType": "CLEARTEXT_PASSWORD",
    "namespacePrefix": "cdp",
    "domain": "$KUBE_DOMAIN",
    "dockerConfigJson": "",
    "description": ""
}
EOF
  # Call createPrivateEnvironment
  "${CURL_POST[@]}" -d @$ECS_ENV_JSON $ECS_BASE_URL/api/v1/environments2/createPrivateEnvironment >/dev/null 2>&1
  while true; do
    [[ $("${CURL_POST[@]}" -d '{"environmentName": "default"}' $ECS_BASE_URL/api/v1/environments2/describeEnvironment 2>/dev/null| jq -r '.environment.status') == "AVAILABLE" ]] && break
    echo "Waiting for environment to be ready.."
    sleep 10
  done

  # Assign DE,DW,ML Access Roles to environment "default"
  ECS_ENV_CRN=$("${CURL_POST[@]}" -d '{"environmentName": "default"}' $ECS_BASE_URL/api/v1/environments2/describeEnvironment 2>/dev/null| jq -r '.environment.crn')
  ECS_ADMIN_ROLES=( 'DEAdmin' 'DWAdmin' 'MLAdmin' )
  for ECS_ROLE in "${ECS_ADMIN_ROLES[@]}"; do
    cat > $ECS_ENV_JSON <<EOF
{
  "resourceCrn": "$ECS_ENV_CRN",
  "resourceRoleCrn": "crn:altus:iam:us-west-1:altus:resourceRole:$ECS_ROLE",
  "groupName": "cdp-admins"
}
EOF
    "${CURL_POST[@]}" -d @$ECS_ENV_JSON $ECS_BASE_URL/api/v1/iam/assignGroupResourceRole >/dev/null 2>&1
  done
  ECS_USER_ROLES=( 'DEUser' 'DWUser' 'MLUser' )
  for ECS_ROLE in "${ECS_USER_ROLES[@]}"; do
    cat > $ECS_ENV_JSON <<EOF
{
  "resourceCrn": "$ECS_ENV_CRN",
  "resourceRoleCrn": "crn:altus:iam:us-west-1:altus:resourceRole:$ECS_ROLE",
  "groupName": "cdp-users"
}
EOF
    "${CURL_POST[@]}" -d @$ECS_ENV_JSON $ECS_BASE_URL/api/v1/iam/assignGroupResourceRole >/dev/null 2>&1
  done

  log_status "Configure NFS for CML Workspace"
  NFS_EXT_DIR=""
  NFS_VER=""
  NFS_DISK_SIZE="100"

  if [[ "${EXTERNAL_NFS}" == "1" ]]; then
    log_status "Prepare NFS for CML"
    enable_nfs
    NFS_EXT_DIR="${ENDPOINT_HOST}:/nfs/workshop"
    NFS_VER="4.1"
    NFS_DISK_SIZE=""
  fi

  log_status "Provision CML Workspace"
  # Build request JSON
  cat > $ECS_CML_JSON <<EOF
{
    "environmentName": "default",
    "workspaceName": "edge2ai",
    "disableTLS": false,
    "enableMonitoring": true,
    "enableGovernance": true,
    "enableModelMetrics": true,
    "existingDatabaseConfig": {},
    "mlGovernancePrincipal": "workshop",
    "staticSubdomain": "edge2ai",
    "existingNFS": "$NFS_EXT_DIR",
    "nfsVersion": "$NFS_VER",
    "namespace": "edge2ai",
    "nfsDiskSize": "$NFS_DISK_SIZE",
    "performCdswMigration": false
}
EOF
  # Call createWorkspace 
  "${CURL_POST[@]}" -d @$ECS_CML_JSON $ECS_BASE_URL/api/v1/ml/createWorkspace 2>/dev/null
  local tries=99
  while [[ $tries -ne 0 ]]; do
    echo "Waiting for CML workspace to be ready.."
    [[ $("${CURL_POST[@]}" -d '{}' $ECS_BASE_URL/api/v1/ml/listWorkspaces 2>/dev/null | jq -r '.workspaces[] | .instanceStatus') == "installation:finished" ]] && break
    ((tries--))
    sleep 10
  done

  # Get CML URL
  CML_BASE_URL=$("${CURL_POST[@]}" -d '{}' $ECS_BASE_URL/api/v1/ml/listWorkspaces 2>/dev/null | jq -r '.workspaces[] | .instanceUrl')
  log_status "Workspace URL=${CML_BASE_URL}"
  log_status "CML Workspace provisioned successfully"
}

# ADD-CML: Model Registry
function install_model_registry() {

  local ENDPOINT_HOST="${1}"  
  local ECS_BASE_URL="https://console-cdp.apps.$ENDPOINT_HOST"
  local ECS_MR_JSON=${BASE_DIR}/modelregistry.json.$$
  local OZONE_BUCKET_NAME="modelregistry"
  local COOKIE_FILE=${BASE_DIR}/cookie.txt.$$

  CURL_POST=(curl -k -X POST -b $COOKIE_FILE -H "Content-Type: application/json")

  log_status "Setting up Model Registry"

  # create_ozone_bucket
  kinit -kt $KEYTABS_DIR/admin.keytab admin
  ozone sh bucket create s3v/$OZONE_BUCKET_NAME
  # get_s3_access
  get_s3_access=( $(ozone s3 getsecret --om-service-id=ozone) )
  S3_ACCESS_KEY="${get_s3_access[0]#*=}"
  S3_SECRET_KEY="${get_s3_access[1]#*=}"

  # Get accountId
  local CDP_ACCOUNT_ID=$(curl -v -k --retry 3 $ECS_BASE_URL/authenticate/login/local 2>&1 | grep "location:" | sed 's/.*accountId=//;s/&.*//')
  # Get a session token
  curl -k -X POST -c $COOKIE_FILE -d "username=admin&password=admin" "$ECS_BASE_URL/authenticate/callback/local?accountId=$CDP_ACCOUNT_ID&state=$ECS_BASE_URL" >/dev/null 2>&1
  # Get CRN
  ECS_ENV_CRN=$("${CURL_POST[@]}" -d '{"environmentName": "default"}' $ECS_BASE_URL/api/v1/environments2/describeEnvironment 2>/dev/null| jq -r '.environment.crn')

  cat > $ECS_MR_JSON <<EOF
{
  "environmentName": "default",
  "s3AccessKey": "$S3_ACCESS_KEY",
  "s3SecretKey": "$S3_SECRET_KEY",
  "s3Bucket": "$OZONE_BUCKET_NAME",
  "s3Endpoint": "https://$CLUSTER_HOST:9879",
  "environmentCrn": "$ECS_ENV_CRN"
}
EOF
  # Call createModelRegistry 
  "${CURL_POST[@]}" -d @$ECS_MR_JSON $ECS_BASE_URL/api/v1/ml/createModelRegistry 2>/dev/null
  local tries=99
  while [[ $tries -ne 0 ]]; do
    echo "Waiting for Model Registry to be ready.."
    [[ $("${CURL_POST[@]}" -d '{}' $ECS_BASE_URL/api/v1/ml/listModelRegistries 2>/dev/null | jq -r '.modelRegistries[] | .status') == "INSTALLED" ]] && break
    ((tries--))
    sleep 10
  done
  # Get Workspace CRN
  WORKSPACE_CRN=$("${CURL_POST[@]}" -d '{}' $ECS_BASE_URL/api/v1/ml/listWorkspaces 2>/dev/null | jq -r '.workspaces[] | .crn')
  # Refresh Edge2AI workspace
  "${CURL_POST[@]}" -d '{"workspaceCrn": "'"$WORKSPACE_CRN"'"}' $ECS_BASE_URL/api/v1/ml/refreshModelRegistryConfigmap 2>/dev/null
  log_status "Model Registry provisioned successfully"
}

function enable_nfs() {
  yum_install nfs-utils
  mkdir /nfs/workshop -p
  chown 8536:8536 /nfs/workshop
  chmod g+srwx /nfs/workshop
  echo "/nfs/workshop  *(rw,sync,no_root_squash,no_all_squash,no_subtree_check)" | tee -a /etc/exports
  systemctl enable nfs-server
  systemctl start nfs-server
  if firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd --permanent --add-service=nfs
    firewall-cmd --permanent --add-service=mountd
    firewall-cmd --permanent --add-service=rpc-bind
    firewall-cmd --reload
    echo "firewall-cmd is running"
  else
    echo "SKIPPED: firewall-cmd is not running or not installed"
  fi
}

# ROCKY8: Add rocky support
function add_rocky_support() {
  lsb_dist="$(. /etc/os-release && echo "$ID")"
  # Add support for Rocky Linux 8
  if [[ $lsb_dist == "rocky" ]]; then
    sed -i 's/Rocky Linux release/Red Hat Enterprise Linux release/' /etc/redhat-release
    sed -i 's/ID="rocky"/ID="rhel"/' /etc/os-release
    if lsblk -o MOUNTPOINT,TYPE | grep -q "^/ .*lvm"; then
        echo "The root disk is on LVM."
        growpart /dev/nvme0n1 5
        lvextend -l +100%FREE /dev/mapper/rocky-root
        xfs_growfs /
    fi
  fi
}
