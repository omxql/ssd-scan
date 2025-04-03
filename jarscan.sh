#!/bin/bash
#Purpose:  This script downloads a Jar file from a web url, and generates sbom file by doing sec scanning the file

#Inputs: Jar Url
#Inputs: ArtifactoryUserName, ArtifactoryToken
#SSDUrl, SSDTeamToken
#GitUrl, GitBranch

# Assign variables from command-line arguments if available
JAR_URL=${JAR_URL:-$1}
ARTIFACTORY_USER=${ARTIFACTORY_USER:-$2}
ARTIFACTORY_PASS=${ARTIFACTORY_PASS:-$3}
SSD_URL=${SSD_URL:-$4}
SSD_TEAMTOKEN=${SSD_TEAMTOKEN:-$5}
GIT_URL=${GIT_URL:-$6}
GIT_BRANCH=${GIT_BRANCH:-$7}

TLS_INSEC=${SKIP_TLS:+-k}

# Check if any variable is unset or empty
if [[ -z "$JAR_URL" || -z "$ARTIFACTORY_USER" || -z "$ARTIFACTORY_PASS" || -z "$SSD_URL" || -z "$SSD_TEAMTOKEN" ]]; then
    echo "Error: Missing required variables."
    echo "Usage: $0 <JAR_URL> <ARTIFACTORY_USER> <ARTIFACTORY_PASS> <SSD_URL> <SSD_TEAMTOKEN>"
    echo "[OR] You can set the variables upfront and simply call the script"
    echo "Usage: $0 "
    echo "Usage: $0 <JAR_URL>"
    exit 1
fi

echo "All required variables are set."

set -e

#Everything is executed from this base directory
[ ! -d ssdscan ] && mkdir ssdscan
cd ssdscan

# Step1: Ensure Grype is installed
if ! command -v grype > /dev/null; then
  echo 'Installing grype...'
  #curl -s https://raw.githubusercontent.com/anchore/grype/main/install.sh | sudo bash
  #Above did not work
  curl -fsSLo grype.tar.gz https://github.com/anchore/grype/releases/download/v0.90.0/grype_0.90.0_linux_amd64.tar.gz
  [ ! -d grype ] && mkdir -p grype && tar -zxvf  grype.tar.gz -C grype/
  chmod +x grype/grype
  sudo install grype/grype /usr/local/bin/
fi
echo "Found $(grype --version)"

# Step2: Download the jar file from Artifactory url
echo -e "\nFetching the Jar file from ${JAR_URL}"
if [ "$SKIP_FETCHJAR" != "true" ]; then
  curl $TLS_INSEC -w "%{http_code}" -fSLO -u${ARTIFACTORY_USER}:${ARTIFACTORY_PASS} ${JAR_URL} 
  if [ $? -eq 0 ]; then
    echo "...done"
  fi
fi
echo 

# Step3: Perform grype scanning / Generate SBOM for Jar file

# Prior to scanning and publishing results, extract the appname, version from the filename
JAR_URLFILE=$(basename $JAR_URL)
#JAR_FILE="spring-petclinic-rel-v3.5.4-main.jar"
JAR_FILE=${JAR_FILE:-$JAR_URLFILE}
#Expected file format
#APP-NAME-ANY-verpreX.Y.Z-tag.ext #AppName & X.Y part is mandatory, verpre(fix) text is optional, .Z is optional, -tag is optional

#Extracting info from filename
#JAR_FILE=spring-petclinic-rel-ver3.5.4-main.jar #Example file
#COMPNAME=spring-petclinic-rel, VERPREFIX=ver, VER=3.5.4, VERSUFFIX=-main
#Pattern matching with sed
#sed -E 's/(.*)-([a-zA-Z]*)([0-9]+\.[0-9]+)(\.[0-9]+)?(-[a-zA-Z0-9]+)?.*/\1 \2 \3 \4 \5/'
# MatchingGroup: \1 - AppName, \2- VerPrefix(optional), \3-Two digit ver, \4-Third digit ver(optional), \5-VerSuffix(optional)
# Example: spring-petclinic-rel-v3.5.4-snapshot.jar
# \1=spring-petclinic-rel, \2=v, \3=3.5, \4=.4, \5=-snapshot

APP_NAME=$(echo "$JAR_FILE" | sed -E 's/(.*)-([a-zA-Z]*)([0-9]+\.[0-9]+)(\.[0-9]+)?(-[a-zA-Z0-9]+)?.*/\1/')
COMP_NAME=$(echo "$JAR_FILE" | sed -E 's/(.*)\..*/\1/')
COMP_VERPREFIX=$(echo "$JAR_FILE" | sed -E 's/(.*)-([a-zA-Z]*)([0-9]+\.[0-9]+)(\.[0-9]+)?(-[a-zA-Z0-9]+)?.*/\2/')
COMP_VERSIONXYZ=$(echo "$JAR_FILE" | sed -E 's/(.*)-([a-zA-Z]*)([0-9]+\.[0-9]+)(\.[0-9]+)?(-[a-zA-Z0-9]+)?.*/\3\4/')
COMP_VERSUFFIX=$(echo "$JAR_FILE" | sed -E 's/(.*)-([a-zA-Z]*)([0-9]+\.[0-9]+)(\.[0-9]+)?(-[a-zA-Z0-9]+)?.*/\5/')
COMP_VERSION=$(echo "$JAR_FILE" | sed -E 's/(.*)-([a-zA-Z]*)([0-9]+\.[0-9]+)(\.[0-9]+)?(-[a-zA-Z0-9]+)?.*/\2\3\4\5/')
FILE_NAME=$(echo "$JAR_FILE" | sed -E 's/(.*)\..*/\1/')
#SBOM_FILE=${JAR_FILE}.sbom.json
SBOM_FILE=${FILE_NAME}.sbom.json
FILE_SHA=$(echo -n $JAR_FILE | sha256sum | awk '{print $1}')

echo "JAR_FILE: $JAR_FILE"
echo "SBOM_FILE: $SBOM_FILE"
echo "FILE_SHA: $FILE_SHA"
echo -n "FILE TYPE ($JAR_FILE) => "
file $JAR_FILE

echo -e "\nGenerating SBOM on the Jar file ..."
echo "File Type: $JAR_FILE"
file $JAR_FILE
grype "$JAR_FILE" --scope all-layers -o cyclonedx-json --file "$SBOM_FILE"

if [ $? -eq 0 ]; then 
  echo "...done" 
fi

# Step 4: Post grype scan result (SBOM) to SSD

echo -e "\nPosting the SBOM result to SSD ..."
echo -e "APP_NAME: $APP_NAME \n$APP_NAME: $COMP_NAME \nCOMP_VERSION: $COMP_VERSION \nFILE_SHA: $FILE_SHA \n"
set -x
curl $TLS_INSEC -w "%{http_code}" -fLS "${SSD_URL}/webhook/api/v1/sbom?artifactName=${COMP_NAME}&artifactTag=${COMP_VERSION}&artifactSha=${FILE_SHA}&tool=grype" \
     --header 'Content-Type: application/json' \
     --header "Authorization: Bearer ${SSD_TEAMTOKEN}" \
     --data-binary "@${SBOM_FILE}"
RET_CODE="$?"
set +x

if [ $RET_CODE -eq 0 ]; then
  echo -e "...done" 
fi

# Step 5: Trigger a build event to SSD (using curl)

echo -e "\nTriggering a build event to SSD ..."
# BOGUS Values just to trigger build event. They are not real
JOB_BASE_NAME="TerminalCurl_Sample"
BUILD_NUMBER="$(date +%Y%m%d%H%M%S)"
CI_HOST="https://ortseam-ci.io"
JOB_URL="$CI_HOST/$JOB_BASE_NAME/$BUILD_NUMBER"
set -x
curl $TLS_INSEC -w "%{http_code}" -fLS "${SSD_URL}/webhook/v1/ssd" \
--header 'Content-Type: application/json' \
--data '{
  "giturl": "'"$GIT_URL"'",
  "gitbranch": "'"$GIT_BRANCH"'",
  "jobname": "'"$JOB_BASE_NAME"'",
  "buildnumber": "'"$BUILD_NUMBER"'",
  "joburl": "'"$JOB_URL"'",
  "builduser": "'"sagay"'",
  "account": "product",
  "applicationname": "ortseam-poc",
  "namespace": "ssd",
  "artifacts": [
    {
      "service": "'"$COMP_NAME"'",
      "nonimage": "'"$COMP_NAME"'|'"$COMP_VERSION"'|'"$JAR_FILE"'",
      "artifacturl": "'"$JAR_URL"'"
    }
  ]
}'

RET_CODE="$?"
set +x

if [ $RET_CODE -eq 0 ]; then
  echo -e "...done" 
fi

set +x
# Step 6: Check SSD for ASPM report
