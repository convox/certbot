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
	reApprovalURL = regexp.MustCompile(`https://certificates.amazon.com/approvals[^\s]+`)
	reDomain      = regexp.MustCompile(`Domain: (.+?\.rack\.convox\.io)`)

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
	body := c.Form("stripped-text")

	d, err := domain(body)
	if err != nil {
		c.LogError(err)
		return err
	}

	c.Tag("domain=%q", d)

	e, err := exists(d)
	fmt.Printf("e = %+v\n", e)
	fmt.Printf("err = %+v\n", err)
	if err != nil {
		return err
	}

	if e {
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
	wildcard := fmt.Sprintf("*.%s", strings.TrimSuffix(domain, ".rack.convox.io"))
	fmt.Printf("wildcard = %+v\n", wildcard)

	res, err := r53.ListResourceRecordSets(&route53.ListResourceRecordSetsInput{
		HostedZoneId:    aws.String(os.Getenv("HOSTED_ZONE")),
		MaxItems:        aws.String("1"),
		StartRecordName: aws.String(wildcard),
	})
	if err != nil {
		return false, err
	}

	return len(res.ResourceRecordSets) > 0, nil
}

func register(domain string) error {
	return nil
}

func approve(aurl string) error {
	if _, err := url.Parse(aurl); aurl == "" || err != nil {
		return fmt.Errorf("invalid url")
	}

	b := surf.NewBrowser()

	if err := b.Open(aurl); err != nil {
		return err
	}

	f, err := b.Form(`form[action="/approvals"]`)
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
