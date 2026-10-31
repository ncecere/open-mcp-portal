package main

import (
	"context"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/ncecere/terraform-provider-omp/internal/provider"
)

func main() {
	if err := providerserver.Serve(context.Background(), provider.New, providerserver.ServeOpts{
		Address: "registry.terraform.io/ncecere/omp",
	}); err != nil {
		log.Fatal("provider could not start")
	}
}
