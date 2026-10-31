terraform {
  required_providers {
    omp = {
      source = "ncecere/omp"
    }
  }
}

# Existing tokens come ONLY from the process environment.
# OMP_TOKEN holds an exact-team publisher token with servers:read.
provider "omp" {
  url = "https://portal.example.com"
}

# OMP_TOKEN_PLATFORM holds a platform token with platform:read.
provider "omp" {
  alias     = "platform"
  url       = "https://portal.example.com"
  token_env = "OMP_TOKEN_PLATFORM"
}

data "omp_team_mcp_server" "status" {
  team   = "bravo"
  lookup = "status"
}

data "omp_team" "bravo" {
  provider = omp.platform
  lookup   = "bravo"
}

output "server_id" {
  value = data.omp_team_mcp_server.status.id
}
