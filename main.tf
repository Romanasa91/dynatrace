############################################
# ECS Fargate + Dynatrace runtime injection
############################################

########################
# Network
########################

data "aws_subnet" "ecs" {
  id = "subnet-089c25c4c11d3c912"
}

resource "aws_security_group" "ecs_service" {
  name        = "dynatrace-ecs"
  description = "Allow all egress for Dynatrace connectivity"
  vpc_id      = data.aws_subnet.ecs.vpc_id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

########################
# Logs
########################

resource "aws_cloudwatch_log_group" "ecs" {
  name              = "/ecs/dynatrace-task"
  retention_in_days = 7
}

########################
# IAM
########################

resource "aws_iam_role" "ecs_task_execution" {
  name = "ecsTaskExecutionRole-dynatrace"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_task_execution_attach" {
  role       = aws_iam_role.ecs_task_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role" "ecs_task" {
  name = "ecsTaskRole-dynatrace"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

########################
# ECS Cluster
########################

resource "aws_ecs_cluster" "this" {
  name = "dyna-saas-test"
}

########################
# Task definition
########################

resource "aws_ecs_task_definition" "dynatrace" {
  family                   = "dynatrace-task"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "512"
  memory                   = "1024"

  execution_role_arn = aws_iam_role.ecs_task_execution.arn
  task_role_arn      = aws_iam_role.ecs_task.arn

  volume {
    name = "oneagent"
  }

  container_definitions = jsonencode([
    {
      name      = "oneagent-installer"
      image     = "alpine:latest"
      essential = false
      entryPoint = ["/bin/sh", "-c"]
      command = ["ARCHIVE=$(mktemp) && wget -O $ARCHIVE \"$DT_API_URL/v1/deployment/installer/agent/unix/paas/latest?arch=$ARCH&Api-Token=$DT_PAAS_TOKEN&$DT_ONEAGENT_OPTIONS\" && unzip -o -d /opt/dynatrace/oneagent $ARCHIVE && rm -f $ARCHIVE"]
      environment = [
        {
          name  = "DT_API_URL"
          value = "https://bls47110.live.dynatrace.com/api"
        },
        {
          name = "DT_PAAS_TOKEN"
          value = "dt0c01.2NZYR7WDIXOF3I5PJXAVHJPE.3MR2CEGBQXQA223J6K3OYFTBPA7VCGWUTTAANXTSJXRP4JZ4CF64E3QK5GX4OVDR"
        },
        {
          name  = "DT_ONEAGENT_OPTIONS"
          value = "flavor=default&include=all"
        },
        {
          name  = "ARCH"
          value = "x86"
        }
      ]
      mountPoints = [
        {
          sourceVolume  = "oneagent"
          containerPath = "/opt/dynatrace/oneagent"
          readOnly      = false
        }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.ecs.name
          awslogs-region        = "eu-central-1"
          awslogs-stream-prefix = "oneagent"
        }
      }
    },
    {
      name      = "app"
      image     = "python:alpine"
      essential = true
      entryPoint = ["/bin/sh", "-c"]
      command = ["apk add --no-cache openssl && python3 - << 'EOF'\nfrom http.server import HTTPServer, SimpleHTTPRequestHandler\nimport ssl, subprocess\nHOST = \"127.0.0.1\"\nPORT = 8443\nsubprocess.run([\"openssl\",\"req\",\"-x509\",\"-newkey\",\"rsa:2048\",\"-keyout\",\"key.pem\",\"-out\",\"cert.pem\",\"-days\",\"365\",\"-nodes\",\"-subj\",\"/CN=localhost\"], check=False)\nhttpd = HTTPServer((HOST, PORT), SimpleHTTPRequestHandler)\nctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)\nctx.load_cert_chain(certfile=\"cert.pem\", keyfile=\"key.pem\")\nhttpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)\nprint(\"HTTPS server on %s:%d\" % (HOST, PORT))\nhttpd.serve_forever()\nEOF\n"]
      dependsOn = [
        {
          containerName = "oneagent-installer"
          condition     = "COMPLETE"
        }
      ]

      environment = [
        {
          name  = "LD_PRELOAD"
          value = "/opt/dynatrace/oneagent/agent/lib64/liboneagentproc.so"
        },
        {
          name  = "DT_LOGLEVELCON"
          value = "info"
        } 
      ]
      mountPoints = [
        {
          sourceVolume  = "oneagent"
          containerPath = "/opt/dynatrace/oneagent"
          readOnly      = false
        }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.ecs.name
          awslogs-region        = "eu-central-1"
          awslogs-stream-prefix = "app"
        }
      }
    }
  ])
}
########################
# ECS Service
########################

resource "aws_ecs_service" "dynatrace" {
  name            = "oneagent-service"
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.dynatrace.arn
  desired_count   = 1
  launch_type     = "FARGATE"
  enable_execute_command   = true

  network_configuration {
    subnets          = [data.aws_subnet.ecs.id]
    security_groups  = [aws_security_group.ecs_service.id]
    assign_public_ip = true
  }

  deployment_minimum_healthy_percent = 0
  deployment_maximum_percent         = 100
}
