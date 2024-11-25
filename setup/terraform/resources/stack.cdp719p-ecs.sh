#!/usr/bin/env bash

# Mandatory component:              BASE
# Common components to CDH and CDP: CDSW, FLINK, HBASE HDFS, HIVE, HUE, IMPALA, KAFKA, KUDU,
#                                   NIFI, OOZIE, SCHEMAREGISTRY, SMM, SRM, SOLR, SPARK_ON_YARN, YARN,
#                                   ZOOKEEPER
# CDP-only components:              ATLAS, KNOX, LIVY, OZONE, RANGER, ZEPPELIN
#
# CDP Data Servicea component:      ECS
# ECS required components:          HIVE, RANGER, ATLAS, HDFS, OZONE
# 
# CML and Model Registry will be provisioned by ECS
# CDSW 1.10.5 supports 8.x-8.9 only 8.10 is not supported
# 
CM_SERVICES=BASE,ZOOKEEPER,HDFS,YARN,HIVE,HUE,IMPALA,KAFKA,KUDU,NIFI,OOZIE,OZONE,SCHEMAREGISTRY,SPARK_ON_YARN,SMM,CDSW,FLINK,SOLR,HBASE,ATLAS,LIVY,ZEPPELIN,RANGER,KNOX,ECS
ENABLE_KERBEROS=yes
KERBEROS_TYPE=IPA
ENABLE_TLS=yes

#####  Java Package
JAVA_PACKAGE_NAME=java-11-openjdk-devel
OPENJDK_VERSION=17.0.2

##### Maven binary
MAVEN_BINARY_URL=https://downloads.apache.org/maven/maven-3/3.9.6/binaries/apache-maven-3.9.6-bin.tar.gz

#####  CM
CM_VERSION=7.11.3.26
CM_MAJOR_VERSION=${CM_VERSION%%.*}
CM_REPO_AS_TARBALL_URL=https://archive.cloudera.com/p/cm${CM_MAJOR_VERSION}/${CM_VERSION}/repo-as-tarball/cm${CM_VERSION}-redhat${MAJOR_OS_VERSION}.tar.gz
CM_BASE_URL=
CM_REPO_FILE_URL=

#####  CDH
CDH_VERSION=7.1.9
CDH_GBN=55406660
CDH_BUILD=${CDH_VERSION}-1.cdh${CDH_VERSION}.p1000.${CDH_GBN}
_CDH_BUILD_PATH=${CDH_VERSION}.1000
CDH_MAJOR_VERSION=${CDH_VERSION%%.*}
CDH_PARCEL_REPO=https://archive.cloudera.com/p/cdh${CDH_MAJOR_VERSION}/${_CDH_BUILD_PATH}/parcels/

#####  CFM
CFM_VERSION=2.1.6.0
CFM_BUILD=${CFM_VERSION}-323
CFM_MAJOR_VERSION=${CFM_VERSION%%.*}
NIFI_VERSION=1.23.1
NIFI_REGISTRY_VERSION=${NIFI_VERSION}
CFM_PARCEL_REPO=https://archive.cloudera.com/p/cfm${CFM_MAJOR_VERSION}/${CFM_VERSION}/redhat8/yum/tars/parcel/
CFM_NIFI_CSD_URL=https://archive.cloudera.com/p/cfm${CFM_MAJOR_VERSION}/${CFM_VERSION}/redhat8/yum/tars/parcel/NIFI-${NIFI_VERSION}.${CFM_BUILD}.jar
CFM_NIFIREG_CSD_URL=https://archive.cloudera.com/p/cfm${CFM_MAJOR_VERSION}/${CFM_VERSION}/redhat8/yum/tars/parcel/NIFIREGISTRY-${NIFI_REGISTRY_VERSION}.${CFM_BUILD}.jar

#####  Anaconda3
ANACONDA_PRODUCT=Anaconda3
ANACONDA_VERSION=2021.05
ANACONDA_PARCEL_REPO=https://repo.anaconda.com/pkgs/misc/parcels/

#####  CDSW
# If version is set, install will be attempted
CDSW_VERSION=1.10.5
CDSW_BUILD=1.10.5.p1.47677668
CDSW_PARCEL_REPO=https://archive.cloudera.com/p/cdsw1/${CDSW_VERSION}/parcels/
CDSW_CSD_URL=https://archive.cloudera.com/p/cdsw1/${CDSW_VERSION}/csd/CLOUDERA_DATA_SCIENCE_WORKBENCH-CDPDC-${CDSW_VERSION}.jar

#####  CEM
CEM_VERSION=2.2.0.0
CEM_BUILD=${CEM_VERSION}-86
CEM_MAJOR_VERSION=${CEM_VERSION%%.*}
EFM_TARBALL_URL=https://archive.cloudera.com/p/CEM/redhat${MAJOR_OS_VERSION}/${CEM_MAJOR_VERSION}.x/updates/${CEM_VERSION}/tars/efm/efm-${CEM_BUILD}-bin.tar.gz

#####  CEM AGENTS
MINIFI_VERSION=1.24.05
MINIFI_BUILD=${MINIFI_VERSION}-b95
MINIFI_TARBALL_URL=https://archive.cloudera.com/p/cem-agents/${MINIFI_VERSION}/ubuntu22/apt/tars/nifi-minifi-cpp/nifi-minifi-cpp-${MINIFI_BUILD}-bin-linux.tar.gz
MINIFITK_TARBALL_URL=https://archive.cloudera.com/p/cem-agents/${MINIFI_VERSION}/ubuntu22/apt/tars/nifi-minifi-cpp/nifi-minifi-cpp-${MINIFI_BUILD}-extra-extensions-linux.tar.gz

#####   CSA
CSA_VERSION=1.12.0.0
CSA_GBN=50079952
CSA_JAR_TARGET=7.1.9.1-158
FLINK_VERSION=1.18.0
FLINK_BUILD=${FLINK_VERSION}-csa${CSA_VERSION}-cdh${CSA_JAR_TARGET}-${CSA_GBN}
CSA_PARCEL_REPO=https://archive.cloudera.com/p/csa/${CSA_VERSION}/parcels/
FLINK_CSD_URL=https://archive.cloudera.com/p/csa/${CSA_VERSION}/csd/FLINK-${FLINK_BUILD}.jar
SSB_CSD_URL=https://archive.cloudera.com/p/csa/${CSA_VERSION}/csd/SQL_STREAM_BUILDER-${FLINK_BUILD}.jar

#####   ECS
ECS_VERSION=1.5.4
ECS_RELEASE=${ECS_VERSION}-b99
ECS_GBN=53854554
ECS_BUILD=${ECS_RELEASE}-ecs-${ECS_RELEASE}.p0.${ECS_GBN}
ECS_REPO=https://archive.cloudera.com/p/cdp-pvc-ds/${ECS_VERSION}/
ECS_PARCEL_REPO=${ECS_REPO}parcels/

# Parcels to be pre-downloaded during install.
# Cloudera Manager will download any parcels that are not already downloaded previously.
CDP_PARCEL_URLS=(
  hadoop         "$CDH_BUILD"                         "$CDH_PARCEL_REPO"
  nifi           "$CFM_BUILD"                         "$CFM_PARCEL_REPO"
  cdsw           "$CDSW_BUILD"                        "$CDSW_PARCEL_REPO"
  flink          "$FLINK_BUILD"                       "$CSA_PARCEL_REPO"
  cdp-pvc        "$ECS_BUILD"                         "$ECS_PARCEL_REPO"
)

CDP_CSD_URLS=(
  $CFM_NIFI_CSD_URL
  $CFM_NIFIREG_CSD_URL
  $CDSW_CSD_URL
  $FLINK_CSD_URL
  $SSB_CSD_URL
)