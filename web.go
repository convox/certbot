package main

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/route53"
	"github.com/convox/api"
	"github.com/headzoo/surf"
)

var (
	reApprovalURL = regexp.MustCompile(`https://[^\.]+\.(?:acm-)?certificates\.amazon\.com/approvals[^\s]+`)
	reDomain      = regexp.MustCompile(`Domain: (.+?\.convox\.site)`)

	r53 *route53.Route53
)

func init() {
	r53 = route53.New(session.Must(session.NewSession()))
}

func main() {
	if err := listen(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}
}

func listen() error {
	server := api.New("template", "david-certbot.ngrok.io")

	server.Route("root", "GET", "/", func(w http.ResponseWriter, r *http.Request, c *api.Context) error {
		w.Write([]byte("ok"))
		return nil
	})

	server.Route("mail", "POST", "/mail", mail)

	return server.Listen("http", ":3000")
}

func mail(w http.ResponseWriter, r *http.Request, c *api.Context) error {
	body := c.Form("body-plain")
	fmt.Printf("body = %+v\n", body)

	d, err := domain(body)
	if err != nil {
		c.LogError(err)
		return err
	}

	c.Tag("domain=%q", d)

	e, err := exists(d)
	if err != nil {
		return err
	}

	if e {
		if strings.Contains(body, "requires your approval to renew") || strings.Contains(body, "To approve this request") {
			c.Logf("approve=renew")

			if err := approve(reApprovalURL.FindString(body)); err != nil {
				c.LogError(err)
				return err
			}

			return nil
		}

		return deny(d)
	}

	if err := register(d); err != nil {
		c.LogError(err)
		return err
	}

	if err := approve(reApprovalURL.FindString(body)); err != nil {
		c.LogError(err)
		return err
	}

	c.Logf("approve=new")

	return c.RenderOK()
}

func domain(body string) (string, error) {
	m := reDomain.FindStringSubmatch(body)

	if len(m) < 2 {
		return "", fmt.Errorf("domain not found")
	}

	return m[1], nil
}

func exists(domain string) (bool, error) {
	wildcard := fmt.Sprintf("\\052.%s.", domain)

	res, err := r53.ListResourceRecordSets(&route53.ListResourceRecordSetsInput{
		HostedZoneId:    aws.String(os.Getenv("HOSTED_ZONE")),
		MaxItems:        aws.String("100"),
		StartRecordName: aws.String(wildcard),
		StartRecordType: aws.String("CNAME"),
	})
	if err != nil {
		return false, err
	}
	if len(res.ResourceRecordSets) < 1 {
		return false, nil
	}

	rr := res.ResourceRecordSets[0]

	if *rr.Type == "CNAME" && *rr.Name == wildcard {
		return true, nil
	}

	return false, nil
}

func register(domain string) error {
	wildcard := fmt.Sprintf("\\052.%s.", domain)
	target := fmt.Sprintf("%s.elb.amazonaws.com", strings.TrimSuffix(domain, ".convox.site"))

	_, err := r53.ChangeResourceRecordSets(&route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(os.Getenv("HOSTED_ZONE")),
		ChangeBatch: &route53.ChangeBatch{
			Changes: []*route53.Change{
				&route53.Change{
					Action: aws.String("CREATE"),
					ResourceRecordSet: &route53.ResourceRecordSet{
						Name: aws.String(wildcard),
						Type: aws.String("CNAME"),
						TTL:  aws.Int64(86400),
						ResourceRecords: []*route53.ResourceRecord{
							&route53.ResourceRecord{Value: aws.String(target)},
						},
					},
				},
			},
		},
	})
	if err != nil {
		return err
	}

	return nil
}

func approve(aurl string) error {
	if _, err := url.Parse(aurl); aurl == "" || err != nil {
		return fmt.Errorf("invalid url: %s", aurl)
	}

	b := surf.NewBrowser()

	if err := b.Open(aurl); err != nil {
		return err
	}

	f, err := b.Form(`form[action*="approv"]`)
	if err != nil {
		return err
	}

	if err := f.Submit(); err != nil {
		return err
	}

	return nil
}

func deny(domain string) error {
	return nil
}
