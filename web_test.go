package main

import (
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/route53"
	"github.com/aws/aws-sdk-go/service/route53/route53iface"
	"github.com/stretchr/testify/assert"
)

type mockedR53 struct {
	route53iface.Route53API
}

func (m *mockedR53) ListResourceRecordSets(in *route53.ListResourceRecordSetsInput) (*route53.ListResourceRecordSetsOutput, error) {
	return &route53.ListResourceRecordSetsOutput{
		ResourceRecordSets: []*route53.ResourceRecordSet{
			{
				Type: aws.String("CNAME"),
				Name: aws.String("\\052.app.router.us.convox.site."),
			},
		},
	}, nil
}

func TestExists(t *testing.T) {
	r53 = &mockedR53{}

	testData := []struct {
		domain string
		expect bool
	}{
		{
			domain: "router.us.convox.site",
			expect: false,
		},
		{
			domain: "app.router.us.convox.site",
			expect: true,
		},
		{
			domain: "admin.router.us.convox.site",
			expect: false,
		},
		{
			domain: "admin.app.router.us.convox.site",
			expect: true,
		},
	}

	for _, td := range testData {
		resp, err := exists(td.domain)
		assert.NoError(t, err, td.domain)
		assert.Equal(t, td.expect, resp, td.domain)
	}
}
