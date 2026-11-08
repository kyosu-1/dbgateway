# Internet-facing ALB (the test client is outside the VPC) that terminates
# TLS with a self-signed certificate for var.hostname and forwards plain
# HTTP to the tasks on 8443.

resource "tls_private_key" "alb" {
  algorithm = "RSA" # ACM imports RSA 2048 and ECDSA P-256/P-384 keys
  rsa_bits  = 2048
}

resource "tls_self_signed_cert" "alb" {
  private_key_pem = tls_private_key.alb.private_key_pem

  subject {
    common_name  = var.hostname
    organization = "dbgateway test"
  }
  dns_names = [var.hostname]

  validity_period_hours = 24 * 30
  allowed_uses          = ["digital_signature", "key_encipherment", "server_auth"]
}

resource "aws_acm_certificate" "alb" {
  private_key      = tls_private_key.alb.private_key_pem
  certificate_body = tls_self_signed_cert.alb.cert_pem

  tags = { Name = var.name }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_lb" "this" {
  name                       = var.name
  internal                   = false
  load_balancer_type         = "application"
  security_groups            = [aws_security_group.alb.id]
  subnets                    = aws_subnet.public[*].id
  drop_invalid_header_fields = true
  # MCP over Streamable HTTP may keep server-sent event streams open.
  idle_timeout = 300

  tags = { Name = var.name }
}

resource "aws_lb_target_group" "this" {
  name                 = var.name
  vpc_id               = aws_vpc.this.id
  target_type          = "ip"
  protocol             = "HTTP"
  port                 = 8443
  deregistration_delay = 10

  health_check {
    path                = "/healthz"
    protocol            = "HTTP"
    matcher             = "200"
    interval            = 10
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }

  tags = { Name = var.name }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.this.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate.alb.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this.arn
  }
}
