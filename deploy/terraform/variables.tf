variable "private_subnets" {
  type    = list(string)
  default = []
}

variable "ecs_security_group" {
  type    = string
  default = ""
}

variable "vpc_connector" {
  type    = string
  default = ""
}

resource "aws_lb_target_group" "aegis" {
  name     = "aegis-tg"
  port     = 8080
  protocol = "HTTP"
  vpc_id   = "vpc-123456" # placeholder
}
