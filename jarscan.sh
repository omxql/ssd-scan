:#!/bin/bash
#Inputs: JfrogArtifactory URL, UserName, Token
#Inputs: Jar Url
#SSD Url, Team Token

# Assign variables from command-line arguments if available
JAR_URL=${JAR_URL:-$1}
ARTIFACTORY_USER=${ARTIFACTORY_USER:-$2}
ARTIFACTORY_PASS=${ARTIFACTORY_PASS:-$3}
SSD_URL=${SSD_URL:-$4}
SSD_TEAMTOKEN=${SSD_TEAMTOKEN:-$5}
GIT_URL=${GIT_URL:-$6}
GIT_BRANCH=${GIT_BRANCH:-$7}

# Check if any variable is unset or empty
if [[ -z "$JAR_URL" || -z "$ARTIFACTORY_USER" || -z "$ARTIFACTORY_PASS" || -z "$SSD_URL" || -z "$SSD_TEAMTOKEN" ]]; then
    echo "Error: Missing required variables."
    echo "Usage: $0 <JAR_URL> <ARTIFACTORY_USER> <ARTIFACTORY_PASS> <SSD_URL> <SSD_TEAMTOKEN>"
    exit 1
fi

echo "All required variables are set."

#if [ $# -ne 5 ]; then
#  echo "Error: Insufficient (or excess) arguments are supplied"
#  echo "Supply 5 arguments: JarArtifactoryUrl, ArtifactoryUser, ArtifactoryPassword, SsdUrl, SsdTeamToken"
#  exit 1
#fi

set -e

#Everything is executed from this base directory
[ ! -d ssdscan ] && mkdir ssdscan
cd ssdscan

# Step1: Ensure Grype is installed
if ! command -v grype > /dev/null; then
  echo 'Installing grype...'
  #curl -s https://raw.githubusercontent.com/anchore/grype/main/install.sh | sudo bash
  #Above did not work
  curl -sSLo grype.tar.gz https://github.com/anchore/grype/releases/download/v0.90.0/grype_0.90.0_linux_amd64.tar.gz
  [ ! -d grype ] && mkdir -p grype && tar -zxvf  grype.tar.gz -C grype/
  chmod +x grype/grype
  sudo install grype/grype /usr/local/bin/
fi
grype --version

# Step2: Download the jar file from Artifactory url
echo "Fetching the Jar file from ${JAR_URL}"
if [ "$SKIP_FETCHJAR" != "true" ]; then
  curl -sSLO -u${ARTIFACTORY_USER}:${ARTIFACTORY_PASS} ${JAR_URL} 
  echo "---done"
fi

# Step3: Perform grype scanning / Generate SBOM for Jar file
JAR_FILE=$(basename $JAR_URL)
SBOM_FILE=${JAR_FILE}.sbom.json
echo $JAR_FILE
echo $SBOM_FILE

echo "Generating SBOM on the Jar file ..."
grype "$JAR_FILE" --scope all-layers -o cyclonedx-json --file "$SBOM_FILE"

if [ $? -eq 0 ]; then 
  echo "...done" 
fi

# Step 4: Post grype scan result (SBOM) to SSD

echo "Posting the SBOM result to SSD ..."
#echo "springpetclinic-3abc-3.4.0-SNAPSHOT.jar" | sed 's/-[0-9][0-9]*\.[0-9].*//'
COMP_NAME=$(echo "$JAR_FILE" | sed 's/\(-.*\)-[0-9][0-9]*\.[0-9].*/\1/')
COMP_VERSION=$(echo "$JAR_FILE" | sed 's/.*-\([0-9][0-9]*\.[0-9].*\)\.jar/\1/')
COMP_SHA=$(echo -n $JAR_FILE | sha256sum | awk '{print $1}')
echo -e "$COMP_NAME \n$COMP_VERSION \n$COMP_SHA \n"

set -x

curl --location "${SSD_URL}/webhook/api/v1/sbom?artifactName=${COMP_NAME}&artifactTag=${COMP_VERSION}&artifactSha=${COMP_SHA}&tool=grype" \
     --header 'Content-Type: application/json' \
     --data-binary "@${SBOM_FILE}" \
     --header "Authorization: Bearer ${SSD_TEAMTOKEN}"
if [ $? -eq 0 ]; then
  echo "...done" 
fi

# Step 5: Trigger a build event to SSD (using curl)

echo "Triggering a build event to SSD ..."
# BOGUS Values just to trigger build event. They are not real
JOB_BASE_NAME="TerminalCurl_Sample"
BUILD_NUMBER="$(date +%Y%m%d%H%M%S)"
JOB_URL="https://sagay-rules.dev/TerminalCurl_Sample/$BUILD_NUMBER"

curl --location "${SSD_URL}/webhook/v1/ssd" \
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

if [ $? -eq 0 ]; then
  echo "...done" 
fi

set +x
# Step 6: Check SSD for ASPM report
