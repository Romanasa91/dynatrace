#!/usr/bin/sh

#!/bin/sh

echo "

██████  ██    ██ ███    ██  █████  ████████ ██████   █████   ██████ ███████
██   ██  ██  ██  ████   ██ ██   ██    ██    ██   ██ ██   ██ ██      ██
██   ██   ████   ██ ██  ██ ███████    ██    ██████  ███████ ██      █████
██   ██    ██    ██  ██ ██ ██   ██    ██    ██   ██ ██   ██ ██      ██
██████     ██    ██   ████ ██   ██    ██    ██   ██ ██   ██  ██████ ███████


 █████   ██████ ████████ ██ ██    ██ ███████      ██████   █████  ████████ ███████      ██████ ██   ██ ███████  ██████ ██   ██ ███████ ██████
██   ██ ██         ██    ██ ██    ██ ██          ██       ██   ██    ██    ██          ██      ██   ██ ██      ██      ██  ██  ██      ██   ██
███████ ██         ██    ██ ██    ██ █████       ██   ███ ███████    ██    █████       ██      ███████ █████   ██      █████   █████   ██████
██   ██ ██         ██    ██  ██  ██  ██          ██    ██ ██   ██    ██    ██          ██      ██   ██ ██      ██      ██  ██  ██      ██   ██
██   ██  ██████    ██    ██   ████   ███████      ██████  ██   ██    ██    ███████      ██████ ██   ██ ███████  ██████ ██   ██ ███████ ██   ██

"


additionalServices=()

while [ "$#" -gt 0 ]; do
  case "$1" in
    --targetAccount=*)
      TARGET_ACCOUNT="${1#*=}"
      ;;
    --targetRole=*)
      TARGET_ROLE="${1#*=}"
      ;;
    --externalId=*)
      EXTERNAL_ID="${1#*=}"
      ;;
    --targetRegion=*)
      TARGET_REGION="${1#*=}"
      ;;
    --additionalServices)
      shift
      while [ "$#" -gt 0 ]; do
        case "$1" in
          --*) break ;;
          *) additionalServices+=("$1") ;;
        esac
        shift
      done
      continue
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
  shift
done

# Validate required arguments
if [[ -z "$TARGET_ACCOUNT" || -z "$TARGET_ROLE" || -z "$TARGET_REGION" || -z "$EXTERNAL_ID" ]]; then
  echo "Error: --targetAccount, --targetRole, --externalId and --targetRegion are required."
  exit 1
fi


# Debug output (optional)
echo "TARGET_ACCOUNT: $TARGET_ACCOUNT"
echo "TARGET_ROLE: $TARGET_ROLE"
echo "TARGET_REGION: $TARGET_REGION"
echo "EXTERNAL_ID": $EXTERNAL_ID
echo "ADDITIONAL_SERVICES: ${additionalServices[*]}"

OS_NAME=$(grep '^NAME=' /etc/os-release | cut -d= -f2 | tr -d '"')

if [ "$OS_NAME" = "Amazon Linux" ]; then
    echo "✔ This is Amazon Linux."
else
    echo "✖ $OS_NAME might not be fully supported yet."
fi

# 1 Am I on AWS?

TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
if curl -s -h "X-aws-ec2-metadata-token: $TOKEN" --connect-timeout 1 http://169.254.169.254/latest/meta-data/instance-id > /dev/null; then
    echo "✔ Running on Amazon EC2"
else
    echo "✖ Not running on Amazon EC2 or EC2 metadata service is not accessible."
    HOSTNAME=$(hostname)
    if [ "${HOSTNAME##*.ec2.internal}" = "" ]; then
        echo "✔ Hostname ends with .ec2.internal"
    else
        #Check if running on EKS
        if [ -z "$KUBERNETES_SERVICE_HOST" ]; then
          echo "✖ Cannot identify platform where AG is running."
        else
          echo "✖ AG is running in kubernetes pod, the outcomes might not be accurate"
        fi

        echo "✖ Hostname does not end with .ec2.internal"
        exit 1
    fi
fi
AG_ACCOUNT_ID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN"  http://169.254.169.254/latest/dynamic/instance-identity/document | grep accountId | awk -F'"' '{print $4}')
# 2 Role info

INSTANCE_PROFILE_ARN=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN"  http://169.254.169.254/latest/meta-data/iam/info |  grep '"InstanceProfileArn"' | sed -E 's/.*: "(.*)",/\1/')
ROLE_NAME=$(echo "$INSTANCE_PROFILE_ARN" | awk -F'/' '{print $2}')

if [ -n "$INSTANCE_PROFILE_ARN" ]; then
  echo "✔ Detected Iam instance profile: $INSTANCE_PROFILE_ARN"
else
  echo "✖ No IAM role detected"
  exit 1
fi

#2.1 Check target role

GET_IDENTITY_RESULT=$(aws sts get-caller-identity --cli-connect-timeout 1)

if echo "$GET_IDENTITY_RESULT" | grep -qi "Connect timeout on endpoint"; then
  ENDPOINT=$(echo "$GET_IDENTITY_RESULT" | grep -oE 'https://[^"]+')
  echo "✖ Connect timeout on endpoint URL: \"$ENDPOINT\""
  exit 1
else
  ENDPOINT=$(echo "$GET_IDENTITY_RESULT" | grep -oE 'https://[^"]+')
  echo "✔ Regional sts endpoint is reachable"
fi

# 2.2 Assume Target role
ASSUME_ROLE_RESULT=$(aws sts assume-role --role-arn arn:aws:iam::${TARGET_ACCOUNT}:role/${TARGET_ROLE} --role-session-name dt-activegate-test --external-id $EXTERNAL_ID --cli-connect-timeout 1 2>&1)
if echo "$ASSUME_ROLE_RESULT" | grep -qi "An error occurred (AccessDenied)"; then
  echo "✖ Target role $TARGET_ROLE in account $TARGET_ACCOUNT cannot be assumed"

  echo "Trying to find root cause..."

  LIST_POLICIES=$(aws iam list-attached-role-policies --role-name "$ROLE_NAME" --query "AttachedPolicies[*].PolicyArn" --output text 2>&1)

  if echo "$LIST_POLICIES" | grep -qi "An error occurred (AccessDenied)"; then
    echo "✖ Permission denied to call \"aws iam list-attached-role-policies\" — cannot do root cause analysis"
  else
    for POLICY_ARN in $LIST_POLICIES; do
      VERSION_ID=$(aws iam get-policy --policy-arn "$POLICY_ARN" --query "Policy.DefaultVersionId" --output text 2>&1)
      if echo "$VERSION_ID" | grep -qi "An error occurred (AccessDenied)"; then
        echo "✖ Permission denied to call \"aws iam get-policy\" — cannot do root cause analysis"
        exit 1
      fi
      POLICY_DOC=$(aws iam get-policy-version --policy-arn "$POLICY_ARN" --version-id "$VERSION_ID" --query "PolicyVersion.Document" --output json 2>&1)
      if echo "$POLICY_DOC" | grep -qi "An error occurred (AccessDenied)"; then
        echo "✖ Permission denied to call \"aws iam get-policy-version\" — cannot do root cause analysis"
        exit 1
      fi
      MATCHES=("sts:AssumeRole" "sts:*")
      HAS_POLICY=false

      for MATCH in "${MATCHES[@]}"; do
        # Escape special characters for grep if needed
        if echo "$POLICY_DOC" | grep -q "\"$MATCH\""; then
          echo "✔ Attached policy '$POLICY_ARN' allows $MATCH"
          HAS_POLICY=true
        fi
      done
    done
    if [ "$HAS_POLICY" = false ]; then
      INLINE_POLICIES=$(aws iam list-role-policies --role-name "$ROLE_NAME" --query "PolicyNames" --output text  --cli-connect-timeout 1 2>&1)
      if echo "$INLINE_POLICIES" | grep -qi "An error occurred (AccessDenied)"; then
          echo "✖ Permission denied to call \"aws iam list-role-policies\" — cannot do root cause analysis"
          exit 1
        else
        for POLICY_NAME in $INLINE_POLICIES; do
          POLICY_DOC=$(aws iam get-role-policy --role-name "$ROLE_NAME" --policy-name "$POLICY_NAME" --query 'PolicyDocument' --output json 2>&1)
          if echo "$POLICY_DOC" | grep -qi "An error occurred (AccessDenied)"; then
            echo "✖ Permission denied to call \"aws iam get-role-policy\" — cannot do root cause analysis"
            exit 1
          fi
          MATCHES=("sts:AssumeRole" "sts:*")
          for MATCH in "${MATCHES[@]}"; do
            if echo "$POLICY_DOC" | grep -q "\"$MATCH\""; then
              echo "✔ Inline policy '$POLICY_ARN' allows $MATCH"
              HAS_POLICY=true
            fi
          done
        done
      fi
    fi
    if [ "$HAS_POLICY" = false ]; then
       echo "✖ No policy allows sts:AssumeRole"
       exit 1
    else
      echo "✖ Cannot check trust policy, please verify manually"
    fi
  fi
  exit 0
else
  echo "✔ IAM role can be assumed"
  AWS_ACCESS_KEY_ID=$(echo "$ASSUME_ROLE_RESULT" | grep -o '"AccessKeyId": *"[^"]*"' | sed 's/.*: *"\([^"]*\)"/\1/')
  AWS_SECRET_ACCESS_KEY=$(echo "$ASSUME_ROLE_RESULT" | grep -o '"SecretAccessKey": *"[^"]*"' | sed 's/.*: *"\([^"]*\)"/\1/')
  AWS_SESSION_TOKEN=$(echo "$ASSUME_ROLE_RESULT" | grep -o '"SessionToken": *"[^"]*"' | sed 's/.*: *"\([^"]*\)"/\1/')
  export AWS_ACCESS_KEY_ID
  export AWS_SECRET_ACCESS_KEY
  export AWS_SESSION_TOKEN
fi

# 3 Check service reachablity
endpoints=(
  "https://sts.${TARGET_REGION}.amazonaws.com/"
  "https://sts.amazonaws.com/"
  "https://tagging.${TARGET_REGION}.amazonaws.com/"
  "https://monitoring.${TARGET_REGION}.amazonaws.com/"
  "https://ec2.${TARGET_REGION}.amazonaws.com"
)

for service in $additionalServices; do
  endpoints+=("https://${service}.${TARGET_REGION}.amazonaws.com/")
done

for url in "${endpoints[@]}"; do
  status_code=$(curl --silent --head --write-out "%{http_code}" --output /dev/null "$url")

  if [[ "$status_code" == "200" || "$status_code" == "400" || "$status_code" == "404" || "$status_code" == "302" || "$status_code" == "403" || "$status_code" == "401" ]]; then
    echo "✔ $url reachable"
  else
    echo "✖ $url not reachable"
  fi
done


#4 Check service permissions

one_hour_ago=$(date -u -d '1 hour ago' +"%Y-%m-%dT%H:%M:%SZ")
twenty_five_hours_ago=$(date -u -d '25 hours ago' +"%Y-%m-%dT%H:%M:%SZ")

GET_METRIC_DATA_OUTPUT=$(aws cloudwatch get-metric-data --metric-data-queries '[{"Id":"m1","MetricStat":{"Metric":{"Namespace":"AWS/Billing","MetricName":"EstimatedCharges","Dimensions":[{"Name":"Currency","Value":"USD"}]},"Period":21600,"Stat":"Maximum"}}]' \
                             --start-time $twenty_five_hours_ago \
                             --end-time $one_hour_ago \
                             --region us-east-1 2>&1)
if echo "$GET_METRIC_DATA_OUTPUT" | grep -qi "An error occurred (AccessDenied)"; then
  echo "✖ Permission denied to call \"aws cloudwatch get-metric-data\""
  exit 1
else
  echo "✔ Metric data accessible in AWS/Billing for EstimatedCharges metric."
fi

GET_METRIC_STATISTICS_OUTPUT=$(aws cloudwatch get-metric-statistics --namespace AWS/EC2 --metric-name CPUUtilization --start-time $twenty_five_hours_ago --end-time $one_hour_ago --period 300 --statistics Average 2>&1)
if echo "$GET_METRIC_STATISTICS_OUTPUT" | grep -qi "An error occurred (AccessDenied)"; then
  echo "✖ Permission denied to call \"aws cloudwatch get-metric-statistics\""
  exit 1
else
  echo "✔ Metric statistics accessible four AWS/EC2 CPUUtilitation."
fi

LIST_METRICS_OUTPUT=$(aws cloudwatch list-metrics --namespace AWS/EC2 2>&1)
if echo "$LIST_METRICS_OUTPUT" | grep -qi "An error occurred (AccessDenied)"; then
  echo "✖ Permission denied to call \"aws list-metrics\""
  exit 1
else
    echo "✔ Able to list metrics in AWS/EC2."
fi

GET_RESOURCES_OUTPUT=$(aws resourcegroupstaggingapi get-resources 2>&1)
if echo "$GET_RESOURCES_OUTPUT" | grep -qi "An error occurred (AccessDeniedException)"; then
  echo "✖ Permission denied to call \"aws resourcegroupstaggingapi get-resources\""
  exit 1
else
    echo "✔ Tagged resources accessible."
fi

GET_TAG_KEYS_OUTPUT=$(aws resourcegroupstaggingapi get-tag-keys 2>&1)
if echo "$GET_TAG_KEYS_OUTPUT" | grep -qi "An error occurred (AccessDeniedException)"; then
  echo "✖ Permission denied to call \"aws resourcegroupstaggingapi get-tag-keys\""
  exit 1
else
    echo "✔ Tag keys accessible."
fi

DESCRIBE_AZ_OUTPUT=$(aws ec2 describe-availability-zones 2>&1)
if echo "$DESCRIBE_AZ_OUTPUT" | grep -qi "An error occurred (UnauthorizedOperation)"; then
  echo "✖ Permission denied to call \"aws ec2 describe-availability-zones\""
  exit 1
else
  echo "✔ Describe AZs is accessible"
fi

unset AWS_ACCESS_KEY_ID
unset AWS_SECRET_ACCESS_KEY
unset AWS_SESSION_TOKEN

exit 0
