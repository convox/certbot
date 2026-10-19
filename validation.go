package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/route53"
	"github.com/convox/api"
)

const (
	recordCap = 500
	stsBody   = "Action=GetCallerIdentity&Version=2011-06-15"
)

var (
	reAccount       = regexp.MustCompile(`^[0-9]{12}$`)
	reAuthorization = regexp.MustCompile(`^AWS4-HMAC-SHA256 Credential=[A-Za-z0-9/_-]+, SignedHeaders=([a-z0-9;-]+), Signature=[0-9a-f]{64}$`)
	reControl       = regexp.MustCompile(`[\x00-\x08\x0a-\x1f\x7f]`)
	reLabel         = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	reRecordName    = regexp.MustCompile(`^_[0-9a-f]{32}$`)
	reRecordValue   = regexp.MustCompile(`^_[0-9a-f]+\.[a-z0-9]+\.acm-validations\.aws\.$`)
	reRegion        = regexp.MustCompile(`^[a-z]{2}(-gov)?-[a-z]+-[0-9]$`)
	reSTS           = regexp.MustCompile(`^https://sts(\.[a-z]{2}(-gov)?-[a-z]+-[0-9])?\.amazonaws\.com/$`)

	forwardHeaders = []string{"Authorization", "Content-Type", "X-Amz-Date", "X-Amz-Security-Token", "X-Convox-Registrar"}
	signedAllowed  = map[string]bool{"content-length": true, "content-type": true, "host": true, "x-amz-date": true, "x-amz-security-token": true, "x-convox-registrar": true}

	errIdentity = api.Errorf(401, "identity not accepted")

	lookupHost = net.LookupHost
	stsClient  = &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
)

type validationRequest struct {
	Identity struct {
		URL     string              `json:"url"`
		Headers map[string][]string `json:"headers"`
		Body    string              `json:"body"`
	} `json:"identity"`
	Domain string `json:"domain"`
	Name   string `json:"name"`
	Value  string `json:"value"`
}

type validationResponse struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func validation(w http.ResponseWriter, r *http.Request, c *api.Context) error {
	code := http.StatusOK

	var body interface{}

	res, err := validate(c, w, r)

	switch t := err.(type) {
	case nil:
		body = res
	case api.Error:
		c.LogError(t)
		code, body = t.Code, map[string]string{"error": t.Error()}
	default:
		c.LogError(err)
		code, body = http.StatusServiceUnavailable, map[string]string{"error": "registrar unavailable"}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)

	return c.RenderJSON(body)
}

func validate(c *api.Context, w http.ResponseWriter, r *http.Request) (*validationResponse, error) {
	var req validationRequest

	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&req); err != nil {
		return nil, api.Errorf(400, "invalid request")
	}

	id := req.Identity

	if id.URL == "" || len(id.Headers) == 0 || id.Body == "" || req.Domain == "" || req.Name == "" || req.Value == "" {
		return nil, api.Errorf(400, "invalid request")
	}

	domain := strings.TrimPrefix(strings.ToLower(req.Domain), "*.")
	name := strings.ToLower(req.Name)
	value := strings.ToLower(req.Value)

	label, site, ok := parseSite(domain)
	if !ok {
		return nil, api.Errorf(400, "invalid domain")
	}

	suffix := "." + domain + "."

	if !strings.HasSuffix(name, suffix) || !reRecordName.MatchString(strings.TrimSuffix(name, suffix)) {
		return nil, api.Errorf(400, "invalid record name")
	}

	if !reRecordValue.MatchString(value) {
		return nil, api.Errorf(400, "invalid record value")
	}

	account, arn, err := identify(id.URL, id.Headers, id.Body)
	if err != nil {
		return nil, err
	}

	res := &validationResponse{Name: name, Value: value}

	current, found, err := record(name)
	if err != nil {
		return nil, err
	}
	if found {
		return matching(res, current)
	}

	target := site + ".elb.amazonaws.com"

	if _, err := lookupHost(target); err != nil {
		if e, ok := err.(*net.DNSError); ok && e.Err == "no such host" {
			return nil, api.Errorf(400, "load balancer not found")
		}
		return nil, err
	}

	host := site + ".convox.site"

	registered, err := exists(host)
	if err != nil {
		return nil, err
	}
	if label != "" && !registered {
		return nil, api.Errorf(400, "load balancer not registered")
	}

	o, err := owner(site)
	if err != nil {
		return nil, err
	}
	if o != "" && o != account {
		return nil, api.Errorf(403, "load balancer belongs to another account")
	}

	changes := []*route53.Change{cname(name, value, 300)}

	// A record under <label> makes it an empty non-terminal, which can stop *.<site> answering for <label> and its subdomains.
	if label != "" {
		for _, h := range []string{fmt.Sprintf("%s.%s.", label, host), fmt.Sprintf("\\052.%s.%s.", label, host)} {
			_, found, err := record(h)
			if err != nil {
				return nil, err
			}
			if !found {
				changes = append(changes, cname(h, target, 86400))
			}
		}
	}

	n := len(changes)
	if !registered {
		n++
	}

	if err := count(account, n); err != nil {
		return nil, err
	}

	if !registered {
		if err := claim(site, account); err != nil {
			uncount(c, account, n)
			return nil, err
		}

		if err := register(host); err != nil {
			if ok, xerr := exists(host); xerr != nil || !ok {
				uncount(c, account, n)
				return nil, err
			}
		} else {
			c.Logf("account=%s arn=%s name=%s value=%s", account, arn, "*."+host+".", target)
		}
	}

	_, err = r53.ChangeResourceRecordSets(&route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(os.Getenv("HOSTED_ZONE")),
		ChangeBatch:  &route53.ChangeBatch{Changes: changes},
	})
	if err != nil {
		uncount(c, account, len(changes))

		current, found, rerr := record(name)
		if rerr != nil || !found {
			return nil, err
		}
		return matching(res, current)
	}

	for _, ch := range changes {
		rr := ch.ResourceRecordSet
		c.Logf("account=%s arn=%s name=%s value=%s", account, arn, *rr.Name, *rr.ResourceRecords[0].Value)
	}

	return res, nil
}

func parseSite(domain string) (string, string, bool) {
	if !strings.HasSuffix(domain, ".convox.site") {
		return "", "", false
	}

	labels := strings.Split(strings.TrimSuffix(domain, ".convox.site"), ".")

	if len(labels) < 2 || len(labels) > 3 || !reRegion.MatchString(labels[len(labels)-1]) {
		return "", "", false
	}

	for _, l := range labels {
		if !reLabel.MatchString(l) {
			return "", "", false
		}
	}

	label := ""
	if len(labels) == 3 {
		label = labels[0]
	}

	return label, strings.Join(labels[len(labels)-2:], "."), true
}

func identify(endpoint string, headers map[string][]string, body string) (string, string, error) {
	if !reSTS.MatchString(endpoint) || body != stsBody {
		return "", "", errIdentity
	}

	h := http.Header{}

	for k, v := range headers {
		ck := http.CanonicalHeaderKey(k)
		if _, ok := h[ck]; ok {
			return "", "", errIdentity
		}
		h[ck] = v
	}

	if v := h["X-Convox-Registrar"]; len(v) != 1 || v[0] != "convox.site" {
		return "", "", errIdentity
	}

	if len(h["Authorization"]) != 1 {
		return "", "", errIdentity
	}

	m := reAuthorization.FindStringSubmatch(h.Get("Authorization"))
	if m == nil {
		return "", "", errIdentity
	}

	signed := map[string]bool{}

	for _, name := range strings.Split(m[1], ";") {
		signed[name] = true
	}

	for name := range signed {
		if !signedAllowed[name] {
			return "", "", errIdentity
		}
	}

	if !signed["host"] || !signed["x-amz-date"] || !signed["x-convox-registrar"] {
		return "", "", errIdentity
	}

	req, err := http.NewRequest("POST", endpoint, strings.NewReader(stsBody))
	if err != nil {
		return "", "", errIdentity
	}

	for _, k := range forwardHeaders {
		switch v := h[k]; len(v) {
		case 0:
		case 1:
			if reControl.MatchString(v[0]) {
				return "", "", errIdentity
			}
			req.Header.Set(k, v[0])
		default:
			return "", "", errIdentity
		}
	}

	res, err := stsClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer res.Body.Close()

	data, err := ioutil.ReadAll(io.LimitReader(res.Body, 64*1024))
	if err != nil {
		return "", "", err
	}

	if res.StatusCode >= 500 || (res.StatusCode == 400 && stsCode(data) == "Throttling") {
		return "", "", fmt.Errorf("sts status %d", res.StatusCode)
	}

	// STS answers in JSON when asked, and an IAM user path can carry XML, so only a real XML document is parsed.
	text := strings.TrimSpace(string(data))

	if res.StatusCode != 200 || res.Header.Get("Content-Type") != "text/xml" || !(strings.HasPrefix(text, "<GetCallerIdentityResponse") || strings.HasPrefix(text, "<?xml")) {
		return "", "", errIdentity
	}

	var out struct {
		XMLName xml.Name `xml:"GetCallerIdentityResponse"`
		Account string   `xml:"GetCallerIdentityResult>Account"`
		Arn     string   `xml:"GetCallerIdentityResult>Arn"`
	}

	if err := xml.Unmarshal(data, &out); err != nil || !reAccount.MatchString(out.Account) || out.Arn == "" {
		return "", "", errIdentity
	}

	return out.Account, out.Arn, nil
}

func stsCode(data []byte) string {
	var e struct {
		Code string `xml:"Error>Code"`
	}

	if err := xml.Unmarshal(data, &e); err != nil {
		return ""
	}

	return e.Code
}

func matching(res *validationResponse, current string) (*validationResponse, error) {
	if strings.TrimSuffix(strings.ToLower(current), ".") != strings.TrimSuffix(res.Value, ".") {
		return nil, api.Errorf(409, "record exists with a different value")
	}

	return res, nil
}

func record(name string) (string, bool, error) {
	res, err := r53.ListResourceRecordSets(&route53.ListResourceRecordSetsInput{
		HostedZoneId:    aws.String(os.Getenv("HOSTED_ZONE")),
		MaxItems:        aws.String("1"),
		StartRecordName: aws.String(name),
		StartRecordType: aws.String("CNAME"),
	})
	if err != nil {
		return "", false, err
	}

	for _, rr := range res.ResourceRecordSets {
		if aws.StringValue(rr.Name) == name && aws.StringValue(rr.Type) == "CNAME" && len(rr.ResourceRecords) > 0 {
			return aws.StringValue(rr.ResourceRecords[0].Value), true, nil
		}
	}

	return "", false, nil
}

func cname(name, value string, ttl int64) *route53.Change {
	return &route53.Change{
		Action: aws.String("CREATE"),
		ResourceRecordSet: &route53.ResourceRecordSet{
			Name:            aws.String(name),
			Type:            aws.String("CNAME"),
			TTL:             aws.Int64(ttl),
			ResourceRecords: []*route53.ResourceRecord{{Value: aws.String(value)}},
		},
	}
}

func owner(site string) (string, error) {
	res, err := ddb.GetItem(&dynamodb.GetItemInput{
		TableName:      aws.String(os.Getenv("VALIDATION_TABLE")),
		Key:            map[string]*dynamodb.AttributeValue{"id": {S: aws.String("lb#" + site)}},
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return "", err
	}

	if a, ok := res.Item["account"]; ok {
		return aws.StringValue(a.S), nil
	}

	return "", nil
}

func claim(site, account string) error {
	_, err := ddb.PutItem(&dynamodb.PutItemInput{
		TableName: aws.String(os.Getenv("VALIDATION_TABLE")),
		Item: map[string]*dynamodb.AttributeValue{
			"id":      {S: aws.String("lb#" + site)},
			"account": {S: aws.String(account)},
			"created": {S: aws.String(time.Now().UTC().Format(time.RFC3339))},
		},
		ConditionExpression: aws.String("attribute_not_exists(id)"),
	})
	if !conditionFailed(err) {
		return err
	}

	o, err := owner(site)
	switch {
	case err != nil:
		return err
	case o == "":
		return fmt.Errorf("owner of %s not readable", site)
	case o != account:
		return api.Errorf(403, "load balancer belongs to another account")
	}

	return nil
}

func count(account string, n int) error {
	in := &dynamodb.UpdateItemInput{
		TableName:                 aws.String(os.Getenv("VALIDATION_TABLE")),
		Key:                       map[string]*dynamodb.AttributeValue{"id": {S: aws.String("account#" + account)}},
		UpdateExpression:          aws.String("ADD records :n"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{":n": {N: aws.String(strconv.Itoa(n))}},
	}

	if n > 0 {
		in.ConditionExpression = aws.String("attribute_not_exists(records) OR records <= :max")
		in.ExpressionAttributeValues[":max"] = &dynamodb.AttributeValue{N: aws.String(strconv.Itoa(recordCap - n))}
	}

	_, err := ddb.UpdateItem(in)
	if conditionFailed(err) {
		return api.Errorf(429, "record limit reached")
	}

	return err
}

func uncount(c *api.Context, account string, n int) {
	if err := count(account, -n); err != nil {
		c.LogError(err)
	}
}

func conditionFailed(err error) bool {
	ae, ok := err.(awserr.Error)
	return ok && ae.Code() == dynamodb.ErrCodeConditionalCheckFailedException
}
