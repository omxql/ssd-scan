#!/bin/bash
#Inputs: gitUrl, gitBranch
#SSD Url, Team Token

# Assign variables from command-line arguments if available
GIT_URL=${GIT_URL:-$1}
GIT_BRANCH=${GIT_BRANCH:-$2}
SSD_URL=${SSD_URL:-$3}
SSD_TEAMTOKEN=${SSD_TEAMTOKEN:-$4}

# Check if any variable is unset or empty
if [[ -z "$GIT_URL" || -z "$GIT_BRANCH" || -z "$SSD_URL" || -z "$SSD_TEAMTOKEN" ]]; then
    echo "Error: Missing required variables."
    echo "Usage: $0 <GIT_URL> <GIT_BRANCH> <SSD_URL> <SSD_TEAMTOKEN>"
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
  curl -sSLo grype.tar.gz https://github.com/anchore/grype/releases/download/v0.90.0/grype_0.90.0_linux_amd64.tar.gz
  [ ! -d grype ] && mkdir -p grype && tar -zxvf  grype.tar.gz -C grype/
  chmod +x grype/grype
  sudo install grype/grype /usr/local/bin/
fi
grype --version

set -x
# Step2: Clone the Git repo
echo "Verifying if Git repo is available locally"
GIT_REPO=$(basename ${GIT_URL})
APP_NAME=$(basename -s .git $GIT_REPO)
GIT_BASEDIR=$APP_NAME
echo -e "Remote Repo: ${GIT_URL} \nLocal Repo: $PWD/$GIT_BASEDIR/.git"

if [[ -d "$PWD/$APP_NAME/.git" ]]; then
  echo "Git Local repo exists already. Skipping clone"
else
  echo "Cloning Git repo $GIT_URL -b $GIT_BRANCH"
  git clone --recurse-submodules $GIT_URL -b $GIT_BRANCH  
  echo "---done"
fi

# Step3: Perform grype scanning / Generate SBOM for Jar file
SBOM_FILE=${APP_NAME}.sbom.json
echo $SBOM_FILE

echo "Generating SBOM for Cpp project - $GIT_BASEDIR ..."
grype dir:$GIT_BASEDIR --scope all-layers -o cyclonedx-json --file "$SBOM_FILE"

if [ $? -eq 0 ]; then 
  echo "...done" 
fi

# Step 4: Post grype scan result (SBOM) to SSD
echo "Posting the SBOM result to SSD ..."
JAR_FILE="${APP_NAME}-$(date +%Y-%m-%d-%H%M).jar"
COMP_NAME=$APP_NAME
COMP_VERSION=$(date +%Y-%m-%d-%H%M)
echo $(date +%Y%m%d%H%M%S) > $JAR_FILE
echo COMP_NAME $COMP_NAME
echo COMP_VERSION $COMP_VERSION
echo JAR_FILE $JAR_FILE

#echo "springpetclinic-3abc-3.4.0-SNAPSHOT.jar" | sed 's/-[0-9][0-9]*\.[0-9].*//'
#COMP_NAME=$(echo "$JAR_FILE" | sed 's/\(-.*\)-[0-9][0-9]*\.[0-9].*/\1/')
#COMP_VERSION=$(echo "$JAR_FILE" | sed 's/.*-\([0-9][0-9]*\.[0-9].*\)\.jar/\1/')
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
  "account": "prod",
  "applicationname": "'"$APP_NAME"'",
  "namespace": "ssd",
  "artifacts": [
    {
      "service": "'"$COMP_NAME"'",
      "nonimage": "'"$COMP_NAME"'|'"$COMP_VERSION"'|'"$JAR_FILE"'"
    }
  ]
}'

if [ $? -eq 0 ]; then
  echo "...done" 
fi

set +x
# Step 6: Check SSD for ASPM report
