resource "aws_ecs_cluster" "aegis" {
  name = "aegis-cluster"
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

resource "aws_ecs_task_definition" "aegis" {
  family                   = "aegis-task"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "256"
  memory                   = "512"

  container_definitions = jsonencode([{
    name                   = "aegis-kernel"
    image                  = "aegis-kernel:latest"
    essential              = true
    user                   = "10001:10001"
    readonlyRootFilesystem = true
    portMappings = [{
      containerPort = 8080
      hostPort      = 8080
    }]
    linuxParameters = {
      capabilities = {
        drop = ["ALL"]
      }
    }
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = "/ecs/aegis-kernel"
        "awslogs-region"        = "us-east-1"
        "awslogs-stream-prefix" = "ecs"
      }
    }
  }])
}

resource "aws_ecs_service" "aegis" {
  name            = "aegis-service"
  cluster         = aws_ecs_cluster.aegis.id
  task_definition = aws_ecs_task_definition.aegis.arn
  desired_count   = 2
  launch_type     = "FARGATE"

  network_configuration {
    subnets         = var.private_subnets
    security_groups = [var.ecs_security_group]
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.aegis.arn
    container_name   = "aegis-kernel"
    container_port   = 8080
  }
}
