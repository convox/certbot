package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/signer/v4"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/aws/aws-sdk-go/service/route53"
	"github.com/aws/aws-sdk-go/service/route53/route53iface"
	"github.com/convox/api"
	"github.com/stretchr/testify/assert"
)

const (
	testAccount  = "123456789012"
	otherAccount = "210987654321"
	testSite     = "myrack-router-123456789.us-east-1"
	testHost     = testSite + ".convox.site"
	testTarget   = testSite + ".elb.amazonaws.com"
	testWildcard = "\\052." + testHost + "."
	testName     = "_0123456789abcdef0123456789abcdef." + testHost + "."
	testValue    = "_fedcba9876543210fedcba9876543210.abcdefghij.acm-validations.aws."
	otherName    = "_abcdefabcdefabcdefabcdefabcdefab." + testHost + "."
	serviceHost  = "myapp-web." + testHost
	serviceName  = "_11111111111111111111111111111111." + serviceHost + "."
	testSecret   = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
)

type fakeR53 struct {
	route53iface.Route53API
	t       *testing.T
	records map[string]string
	batches [][]*route53.Change
	lists   int
	create  func([]*route53.Change) error
}

func (f *fakeR53) ListResourceRecordSets(in *route53.ListResourceRecordSetsInput) (*route53.ListResourceRecordSetsOutput, error) {
	f.lists++

	name := aws.StringValue(in.StartRecordName)
	rr := &route53.ResourceRecordSet{Name: aws.String("\\052.zz." + testHost + "."), Type: aws.String("CNAME"), ResourceRecords: []*route53.ResourceRecord{{Value: aws.String(testValue)}}}

	if v, ok := f.records[name]; ok {
		rr = &route53.ResourceRecordSet{Name: aws.String(name), Type: aws.String("CNAME"), ResourceRecords: []*route53.ResourceRecord{{Value: aws.String(v)}}}
	}

	return &route53.ListResourceRecordSetsOutput{ResourceRecordSets: []*route53.ResourceRecordSet{rr}}, nil
}

func (f *fakeR53) ChangeResourceRecordSets(in *route53.ChangeResourceRecordSetsInput) (*route53.ChangeResourceRecordSetsOutput, error) {
	changes := in.ChangeBatch.Changes

	for _, c := range changes {
		if a := aws.StringValue(c.Action); a != "CREATE" {
			f.t.Errorf("route 53 %s sent", a)
		}
	}

	if f.create != nil {
		if err := f.create(changes); err != nil {
			return nil, err
		}
	}

	for _, c := range changes {
		if _, ok := f.records[aws.StringValue(c.ResourceRecordSet.Name)]; ok {
			return nil, awserr.New(route53.ErrCodeInvalidChangeBatch, "already exists", nil)
		}
	}

	for _, c := range changes {
		f.records[aws.StringValue(c.ResourceRecordSet.Name)] = aws.StringValue(c.ResourceRecordSet.ResourceRecords[0].Value)
	}

	f.batches = append(f.batches, changes)

	return &route53.ChangeResourceRecordSetsOutput{}, nil
}

type fakeDDB struct {
	dynamodbiface.DynamoDBAPI
	t        *testing.T
	owners   map[string]string
	counts   map[string]int
	calls    int
	err      error
	hidden   bool
	afterGet func()
}

func (f *fakeDDB) GetItem(in *dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
	f.calls++

	if !aws.BoolValue(in.ConsistentRead) {
		f.t.Error("GetItem without ConsistentRead")
	}

	if f.err != nil {
		return nil, f.err
	}

	out := &dynamodb.GetItemOutput{}

	if a, ok := f.owners[aws.StringValue(in.Key["id"].S)]; ok && !f.hidden {
		out.Item = map[string]*dynamodb.AttributeValue{"account": {S: aws.String(a)}}
	}

	if f.afterGet != nil {
		fn := f.afterGet
		f.afterGet = nil
		fn()
	}

	return out, nil
}

func (f *fakeDDB) PutItem(in *dynamodb.PutItemInput) (*dynamodb.PutItemOutput, error) {
	f.calls++

	if f.err != nil {
		return nil, f.err
	}

	assert.Equal(f.t, "attribute_not_exists(id)", aws.StringValue(in.ConditionExpression))

	if _, err := time.Parse(time.RFC3339, aws.StringValue(in.Item["created"].S)); err != nil {
		f.t.Errorf("created: %s", err)
	}

	id := aws.StringValue(in.Item["id"].S)

	if _, ok := f.owners[id]; ok {
		return nil, awserr.New(dynamodb.ErrCodeConditionalCheckFailedException, "condition failed", nil)
	}

	f.owners[id] = aws.StringValue(in.Item["account"].S)

	return &dynamodb.PutItemOutput{}, nil
}

func (f *fakeDDB) UpdateItem(in *dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error) {
	f.calls++

	if f.err != nil {
		return nil, f.err
	}

	assert.Equal(f.t, "ADD records :n", aws.StringValue(in.UpdateExpression))

	id := aws.StringValue(in.Key["id"].S)
	n, _ := strconv.Atoi(aws.StringValue(in.ExpressionAttributeValues[":n"].N))

	if in.ConditionExpression != nil {
		assert.Equal(f.t, "attribute_not_exists(records) OR records <= :max", aws.StringValue(in.ConditionExpression))

		max, _ := strconv.Atoi(aws.StringValue(in.ExpressionAttributeValues[":max"].N))

		if cur, ok := f.counts[id]; ok && cur > max {
			return nil, awserr.New(dynamodb.ErrCodeConditionalCheckFailedException, "condition failed", nil)
		}
	} else if len(in.ExpressionAttributeValues) != 1 {
		f.t.Errorf("unused expression values: %v", in.ExpressionAttributeValues)
	}

	f.counts[id] += n

	return &dynamodb.UpdateItemOutput{}, nil
}

type fakeSTS struct {
	t           *testing.T
	status      int
	contentType string
	body        string
	requests    []*http.Request
}

func (f *fakeSTS) RoundTrip(r *http.Request) (*http.Response, error) {
	f.requests = append(f.requests, r)

	return &http.Response{
		StatusCode: f.status,
		Header:     http.Header{"Content-Type": {f.contentType}},
		Body:       ioutil.NopCloser(strings.NewReader(f.body)),
		Request:    r,
	}, nil
}

func identityResponse(account string) string {
	return fmt.Sprintf(`<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Arn>arn:aws:sts::%s:assumed-role/myrack-ApiRole-ABC/i-0123</Arn>
    <UserId>AROAEXAMPLE:i-0123</UserId>
    <Account>%s</Account>
  </GetCallerIdentityResult>
  <ResponseMetadata>
    <RequestId>01234567-89ab-cdef-0123-456789abcdef</RequestId>
  </ResponseMetadata>
</GetCallerIdentityResponse>
`, account, account)
}

type fakes struct {
	r53     *fakeR53
	ddb     *fakeDDB
	sts     *fakeSTS
	hosts   map[string]error
	lookups int
}

func setup(t *testing.T) *fakes {
	f := &fakes{
		r53:   &fakeR53{t: t, records: map[string]string{}},
		ddb:   &fakeDDB{t: t, owners: map[string]string{}, counts: map[string]int{}},
		sts:   &fakeSTS{t: t, status: 200, contentType: "text/xml", body: identityResponse(testAccount)},
		hosts: map[string]error{testTarget: nil},
	}

	r53o, ddbo, stso, lookupo := r53, ddb, stsClient.Transport, lookupHost

	r53, ddb, stsClient.Transport = f.r53, f.ddb, f.sts
	lookupHost = func(host string) ([]string, error) {
		f.lookups++
		err, ok := f.hosts[host]
		if !ok {
			return nil, &net.DNSError{Err: "no such host", Name: host}
		}
		if err != nil {
			return nil, err
		}
		return []string{"192.0.2.1"}, nil
	}

	t.Cleanup(func() {
		r53, ddb, stsClient.Transport, lookupHost = r53o, ddbo, stso, lookupo
	})

	return f
}

func (f *fakes) outbound() int {
	return len(f.sts.requests) + f.r53.lists + len(f.r53.batches) + f.ddb.calls + f.lookups
}

func sign(t *testing.T, url, token string, at time.Time, prepare func(*http.Request)) http.Header {
	r, err := http.NewRequest("POST", url, strings.NewReader(stsBody))
	if err != nil {
		t.Fatal(err)
	}

	r.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	r.Header.Set("Content-Length", "43")
	r.Header.Set("X-Convox-Registrar", "convox.site")

	if prepare != nil {
		prepare(r)
	}

	if _, err := v4.NewSigner(credentials.NewStaticCredentials("AKIDEXAMPLE", testSecret, token)).Sign(r, strings.NewReader(stsBody), "sts", "us-east-1", at); err != nil {
		t.Fatal(err)
	}

	r.Header.Set("User-Agent", "aws-sdk-go/1.55.8 (go1.25; linux; amd64)")

	return r.Header
}

func identity(t *testing.T) map[string]interface{} {
	return map[string]interface{}{
		"url":     "https://sts.amazonaws.com/",
		"headers": sign(t, "https://sts.amazonaws.com/", "session-token", time.Now(), nil),
		"body":    stsBody,
	}
}

func request(t *testing.T, domain, name, value string) map[string]interface{} {
	return map[string]interface{}{
		"identity": identity(t),
		"domain":   domain,
		"name":     name,
		"value":    value,
	}
}

func post(t *testing.T, body interface{}) (int, string) {
	data, ok := body.([]byte)
	if !ok {
		var err error
		if data, err = json.Marshal(body); err != nil {
			t.Fatal(err)
		}
	}

	s := api.New("test", "localhost")
	s.Route("validation", "POST", "/validation", validation)

	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest("POST", "/validation", bytes.NewReader(data)))

	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var out map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("body %q: %s", w.Body.String(), err)
	}

	if e, ok := out["error"]; ok {
		return w.Code, e
	}

	assert.Equal(t, map[string]string{"name": out["name"], "value": out["value"]}, out)

	return w.Code, out["name"] + " " + out["value"]
}

func TestValidationRequestChecks(t *testing.T) {
	tests := []struct {
		label  string
		body   interface{}
		code   int
		result string
	}{
		{"not json", []byte(`{"domain":`), 400, "invalid request"},
		{"empty", map[string]interface{}{}, 400, "invalid request"},
		{"no identity", map[string]interface{}{"domain": "*." + testHost, "name": testName, "value": testValue}, 400, "invalid request"},
		{"no value", map[string]interface{}{"identity": identity(t), "domain": "*." + testHost, "name": testName}, 400, "invalid request"},
		{"too large", map[string]interface{}{"identity": identity(t), "domain": "*." + testHost, "name": testName, "value": strings.Repeat("a", 70000)}, 400, "invalid request"},
		{"other zone", request(t, "*.myrack-router-123456789.us-east-1.example.com", "_0123456789abcdef0123456789abcdef.myrack-router-123456789.us-east-1.example.com.", testValue), 400, "invalid domain"},
		{"zone apex", request(t, "convox.site", "_0123456789abcdef0123456789abcdef.convox.site.", testValue), 400, "invalid domain"},
		{"region only", request(t, "us-east-1.convox.site", "_0123456789abcdef0123456789abcdef.us-east-1.convox.site.", testValue), 400, "invalid domain"},
		{"too deep", request(t, "a.b."+testHost, "_0123456789abcdef0123456789abcdef.a.b."+testHost+".", testValue), 400, "invalid domain"},
		{"bad region", request(t, "myrack-router-123456789.useast1.convox.site", "_0123456789abcdef0123456789abcdef.myrack-router-123456789.useast1.convox.site.", testValue), 400, "invalid domain"},
		{"bad label", request(t, "-myrack."+"us-east-1.convox.site", "_0123456789abcdef0123456789abcdef.-myrack.us-east-1.convox.site.", testValue), 400, "invalid domain"},
		{"double wildcard", request(t, "*.*."+testHost, testName, testValue), 400, "invalid domain"},
		{"name without trailing dot", request(t, "*."+testHost, strings.TrimSuffix(testName, "."), testValue), 400, "invalid record name"},
		{"name for another domain", request(t, "*."+testHost, "_0123456789abcdef0123456789abcdef.other-router-1.us-east-1.convox.site.", testValue), 400, "invalid record name"},
		{"name short hash", request(t, "*."+testHost, "_0123456789abcdef."+testHost+".", testValue), 400, "invalid record name"},
		{"name extra label", request(t, "*."+testHost, "_0123456789abcdef0123456789abcdef.x."+testHost+".", testValue), 400, "invalid record name"},
		{"value other domain", request(t, "*."+testHost, testName, "_fedcba9876543210fedcba9876543210.abcdefghij.example.com."), 400, "invalid record value"},
		{"value without trailing dot", request(t, "*."+testHost, testName, strings.TrimSuffix(testValue, ".")), 400, "invalid record value"},
	}

	for _, tt := range tests {
		t.Run(tt.label, func(t *testing.T) {
			f := setup(t)

			code, result := post(t, tt.body)
			assert.Equal(t, tt.code, code)
			assert.Equal(t, tt.result, result)
			assert.Equal(t, 0, f.outbound())
		})
	}
}

func TestValidationIdentity(t *testing.T) {
	now := time.Now()

	tests := []struct {
		label       string
		url         string
		headers     http.Header
		body        string
		status      int
		contentType string
		response    string
		code        int
		result      string
		forwarded   bool
	}{
		{label: "regional", url: "https://sts.us-east-1.amazonaws.com/", code: 200, forwarded: true},
		{label: "govcloud", url: "https://sts.us-gov-west-1.amazonaws.com/", code: 200, forwarded: true},
		{label: "no registrar", headers: sign(t, "https://sts.amazonaws.com/", "", now, func(r *http.Request) { r.Header.Del("X-Convox-Registrar") }), code: 401},
		{label: "registrar not signed", headers: func() http.Header {
			h := sign(t, "https://sts.amazonaws.com/", "", now, func(r *http.Request) { r.Header.Del("X-Convox-Registrar") })
			h.Set("X-Convox-Registrar", "convox.site")
			return h
		}(), code: 401},
		{label: "registrar wrong value", headers: sign(t, "https://sts.amazonaws.com/", "", now, func(r *http.Request) { r.Header.Set("X-Convox-Registrar", "vault") }), code: 401},
		{label: "registrar two spellings", headers: func() http.Header {
			h := sign(t, "https://sts.amazonaws.com/", "", now, nil)
			h["x-convox-registrar"] = []string{"convox.site"}
			return h
		}(), code: 401},
		{label: "registrar in a second SignedHeaders", headers: func() http.Header {
			h := sign(t, "https://sts.amazonaws.com/", "", now, func(r *http.Request) { r.Header.Del("X-Convox-Registrar") })
			h.Set("Authorization", strings.Replace(h.Get("Authorization"), ", SignedHeaders=", ", SignedHeaders=host;x-amz-date;x-convox-registrar, SignedHeaders=", 1))
			h.Set("X-Convox-Registrar", "convox.site")
			return h
		}(), code: 401},
		{label: "authorization with control character", headers: func() http.Header {
			h := sign(t, "https://sts.amazonaws.com/", "", now, nil)
			h.Set("Authorization", strings.Replace(h.Get("Authorization"), "Credential=", "Credential=\x01", 1))
			return h
		}(), code: 401},
		{label: "token with control character", headers: sign(t, "https://sts.amazonaws.com/", "token\r\nX-Injected: 1", now, nil), code: 401},
		{label: "accept signed", headers: sign(t, "https://sts.amazonaws.com/", "", now, func(r *http.Request) { r.Header.Set("Accept", "application/json") }), code: 401},
		{label: "two authorizations", headers: func() http.Header {
			h := sign(t, "https://sts.amazonaws.com/", "", now, nil)
			h.Add("Authorization", h.Get("Authorization"))
			return h
		}(), code: 401},
		{label: "other host", url: "https://sts.example.com/", code: 401},
		{label: "s3 bucket host", url: "https://sts.s3.amazonaws.com/", code: 401},
		{label: "plain http", url: "http://sts.amazonaws.com/", code: 401},
		{label: "query string", url: "https://sts.amazonaws.com/?Action=AssumeRoleWithWebIdentity", code: 401},
		{label: "no path", url: "https://sts.amazonaws.com", code: 401},
		{label: "other action", body: "Action=AssumeRole&Version=2011-06-15", code: 401},
		{label: "sts denied", status: 403, response: `<ErrorResponse><Error><Code>SignatureDoesNotMatch</Code></Error></ErrorResponse>`, code: 401, forwarded: true},
		{label: "sts json", contentType: "application/json", response: `{"GetCallerIdentityResponse":{"GetCallerIdentityResult":{"Account":"123456789012","Arn":"arn:aws:iam::123456789012:user/x"}}}`, code: 401, forwarded: true},
		{label: "sts xml as json", contentType: "application/json", code: 401, forwarded: true},
		{label: "sts json with injected xml", response: `{"GetCallerIdentityResponse":{"GetCallerIdentityResult":{"Account":"999999999999","Arn":"arn:aws:iam::999999999999:user/<GetCallerIdentityResponse><GetCallerIdentityResult><Account>123456789012</Account><Arn>x</Arn></GetCallerIdentityResult></GetCallerIdentityResponse>/x"}}}`, code: 401, forwarded: true},
		{label: "sts bad account", response: strings.Replace(identityResponse(testAccount), "<Account>123456789012", "<Account>12345", 1), code: 401, forwarded: true},
		{label: "sts expired token", status: 400, response: `<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><Error><Type>Sender</Type><Code>ExpiredToken</Code><Message>expired</Message></Error></ErrorResponse>`, code: 401, forwarded: true},
		{label: "sts throttled", status: 400, response: `<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><Error><Type>Sender</Type><Code>Throttling</Code><Message>Rate exceeded</Message></Error></ErrorResponse>`, code: 503, forwarded: true},
		{label: "sts failure", status: 500, response: "internal", code: 503, forwarded: true},
	}

	for _, tt := range tests {
		t.Run(tt.label, func(t *testing.T) {
			f := setup(t)
			f.r53.records[testWildcard] = testTarget

			url := tt.url
			if url == "" {
				url = "https://sts.amazonaws.com/"
			}

			headers := tt.headers
			if headers == nil {
				headers = sign(t, url, "", now, nil)
			}

			body := tt.body
			if body == "" {
				body = stsBody
			}

			if tt.status != 0 {
				f.sts.status = tt.status
			}
			if tt.contentType != "" {
				f.sts.contentType = tt.contentType
			}
			if tt.response != "" {
				f.sts.body = tt.response
			}

			req := request(t, "*."+testHost, testName, testValue)
			req["identity"] = map[string]interface{}{"url": url, "headers": headers, "body": body}

			code, result := post(t, req)
			assert.Equal(t, tt.code, code)

			switch tt.code {
			case 200:
				assert.Equal(t, testName+" "+testValue, result)
			case 401:
				assert.Equal(t, "identity not accepted", result)
			case 503:
				assert.Equal(t, "registrar unavailable", result)
			}

			if tt.forwarded {
				assert.Len(t, f.sts.requests, 1)
			} else {
				assert.Len(t, f.sts.requests, 0)
			}

			if tt.code != 200 {
				assert.Equal(t, 0, f.r53.lists+len(f.r53.batches)+f.ddb.calls+f.lookups)
			}
		})
	}
}

func TestValidationForwardsSignedRequest(t *testing.T) {
	for _, token := range []string{"", "session-token"} {
		t.Run(fmt.Sprintf("token=%t", token != ""), func(t *testing.T) {
			f := setup(t)
			f.r53.records[testWildcard] = testTarget

			at := time.Now().UTC().Truncate(time.Second)
			headers := sign(t, "https://sts.amazonaws.com/", token, at, nil)

			req := request(t, "*."+testHost, testName, testValue)
			req["identity"] = map[string]interface{}{"url": "https://sts.amazonaws.com/", "headers": headers, "body": stsBody}

			code, _ := post(t, req)
			assert.Equal(t, 200, code)
			assert.Len(t, f.sts.requests, 1)

			out := f.sts.requests[0]
			assert.Equal(t, "POST", out.Method)
			assert.Equal(t, "https://sts.amazonaws.com/", out.URL.String())
			assert.Equal(t, int64(43), out.ContentLength)
			assert.Empty(t, out.TransferEncoding)

			for k := range out.Header {
				assert.Contains(t, []string{"Authorization", "Content-Type", "X-Amz-Date", "X-Amz-Security-Token", "X-Convox-Registrar"}, k)
			}
			assert.Equal(t, token != "", out.Header.Get("X-Amz-Security-Token") != "")

			resigned, err := http.NewRequest("POST", out.URL.String(), strings.NewReader(stsBody))
			if err != nil {
				t.Fatal(err)
			}
			for k, v := range out.Header {
				if k != "Authorization" {
					resigned.Header[k] = v
				}
			}
			resigned.Header.Set("Content-Length", strconv.FormatInt(out.ContentLength, 10))
			if _, err := v4.NewSigner(credentials.NewStaticCredentials("AKIDEXAMPLE", testSecret, token)).Sign(resigned, strings.NewReader(stsBody), "sts", "us-east-1", at); err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, headers.Get("Authorization"), out.Header.Get("Authorization"))
			assert.Equal(t, headers.Get("Authorization"), resigned.Header.Get("Authorization"))
		})
	}
}

func TestValidationLegacyName(t *testing.T) {
	f := setup(t)
	f.r53.records[testWildcard] = testTarget
	f.sts.body = identityResponse(otherAccount)

	code, result := post(t, request(t, "*.MyRack-Router-123456789.US-East-1.convox.site", strings.ToUpper(testName), testValue))
	assert.Equal(t, 200, code)
	assert.Equal(t, testName+" "+testValue, result)

	assert.Empty(t, f.ddb.owners)
	assert.Equal(t, map[string]int{"account#" + otherAccount: 1}, f.ddb.counts)
	assert.Len(t, f.r53.batches, 1)
	assert.Len(t, f.r53.batches[0], 1)
	assert.Equal(t, testValue, f.r53.records[testName])
	assert.Equal(t, int64(300), aws.Int64Value(f.r53.batches[0][0].ResourceRecordSet.TTL))
}

func TestValidationNewName(t *testing.T) {
	f := setup(t)

	code, _ := post(t, request(t, "*."+testHost, testName, testValue))
	assert.Equal(t, 200, code)

	assert.Equal(t, map[string]string{"lb#" + testSite: testAccount}, f.ddb.owners)
	assert.Equal(t, map[string]int{"account#" + testAccount: 2}, f.ddb.counts)
	assert.Equal(t, testTarget, f.r53.records[testWildcard])
	assert.Equal(t, testValue, f.r53.records[testName])

	f.sts.body = identityResponse(otherAccount)

	code, result := post(t, request(t, "*."+testHost, otherName, testValue))
	assert.Equal(t, 403, code)
	assert.Equal(t, "load balancer belongs to another account", result)
	assert.NotContains(t, f.r53.records, otherName)
	assert.NotContains(t, f.ddb.counts, "account#"+otherAccount)

	f.sts.body = identityResponse(testAccount)

	code, _ = post(t, request(t, "*."+testHost, otherName, testValue))
	assert.Equal(t, 200, code)
	assert.Equal(t, testValue, f.r53.records[otherName])
}

func TestValidationClaimedBeforeRegister(t *testing.T) {
	f := setup(t)
	f.ddb.owners["lb#"+testSite] = testAccount

	code, _ := post(t, request(t, "*."+testHost, testName, testValue))
	assert.Equal(t, 200, code)
	assert.Equal(t, testTarget, f.r53.records[testWildcard])
	assert.Equal(t, testValue, f.r53.records[testName])
}

func TestValidationClaimRace(t *testing.T) {
	f := setup(t)
	f.ddb.afterGet = func() {
		f.ddb.owners["lb#"+testSite] = otherAccount
		f.r53.records[testWildcard] = testTarget
	}

	code, result := post(t, request(t, "*."+testHost, testName, testValue))
	assert.Equal(t, 403, code)
	assert.Equal(t, "load balancer belongs to another account", result)
	assert.Empty(t, f.r53.batches)
	assert.NotContains(t, f.r53.records, testName)
	assert.Equal(t, 0, f.ddb.counts["account#"+testAccount])
}

func TestValidationOwnerUnreadable(t *testing.T) {
	f := setup(t)
	f.ddb.owners["lb#"+testSite] = otherAccount
	f.ddb.hidden = true

	code, result := post(t, request(t, "*."+testHost, testName, testValue))
	assert.Equal(t, 503, code)
	assert.Equal(t, "registrar unavailable", result)
	assert.Empty(t, f.r53.batches)
	assert.Equal(t, 0, f.ddb.counts["account#"+testAccount])
}

func TestValidationRegisterRace(t *testing.T) {
	f := setup(t)
	f.r53.create = func(changes []*route53.Change) error {
		if aws.StringValue(changes[0].ResourceRecordSet.Name) == testWildcard {
			f.r53.records[testWildcard] = testTarget
		}
		return nil
	}

	code, _ := post(t, request(t, "*."+testHost, testName, testValue))
	assert.Equal(t, 200, code)
	assert.Equal(t, testValue, f.r53.records[testName])
}

func TestValidationServiceLevel(t *testing.T) {
	f := setup(t)
	f.r53.records[testWildcard] = testTarget

	code, result := post(t, request(t, "*."+serviceHost, serviceName, testValue))
	assert.Equal(t, 200, code)
	assert.Equal(t, serviceName+" "+testValue, result)

	assert.Len(t, f.r53.batches, 1)
	assert.Len(t, f.r53.batches[0], 3)
	assert.Equal(t, testValue, f.r53.records[serviceName])
	assert.Equal(t, testTarget, f.r53.records[serviceHost+"."])
	assert.Equal(t, testTarget, f.r53.records["\\052."+serviceHost+"."])
	assert.Equal(t, int64(86400), aws.Int64Value(f.r53.batches[0][1].ResourceRecordSet.TTL))
	assert.Equal(t, 3, f.ddb.counts["account#"+testAccount])
	assert.Empty(t, f.ddb.owners)
}

func TestValidationServiceLevelExistingWildcard(t *testing.T) {
	f := setup(t)
	f.r53.records[testWildcard] = testTarget
	f.r53.records["\\052."+serviceHost+"."] = "myapp-web." + testTarget

	code, _ := post(t, request(t, "*."+serviceHost, serviceName, testValue))
	assert.Equal(t, 200, code)

	assert.Len(t, f.r53.batches, 1)
	assert.Len(t, f.r53.batches[0], 2)
	assert.Equal(t, serviceName, aws.StringValue(f.r53.batches[0][0].ResourceRecordSet.Name))
	assert.Equal(t, serviceHost+".", aws.StringValue(f.r53.batches[0][1].ResourceRecordSet.Name))
	assert.Equal(t, "myapp-web."+testTarget, f.r53.records["\\052."+serviceHost+"."])
	assert.Equal(t, 2, f.ddb.counts["account#"+testAccount])
}

func TestValidationServiceLevelUnregistered(t *testing.T) {
	f := setup(t)

	code, result := post(t, request(t, "*."+serviceHost, serviceName, testValue))
	assert.Equal(t, 400, code)
	assert.Equal(t, "load balancer not registered", result)
	assert.Empty(t, f.r53.batches)
	assert.Empty(t, f.ddb.counts)
}

func TestValidationLoadBalancerLookup(t *testing.T) {
	f := setup(t)
	delete(f.hosts, testTarget)

	code, result := post(t, request(t, "*."+testHost, testName, testValue))
	assert.Equal(t, 400, code)
	assert.Equal(t, "load balancer not found", result)

	f.hosts[testTarget] = &net.DNSError{Err: "server misbehaving", Name: testTarget}

	code, result = post(t, request(t, "*."+testHost, testName, testValue))
	assert.Equal(t, 503, code)
	assert.Equal(t, "registrar unavailable", result)

	assert.Empty(t, f.r53.batches)
	assert.Empty(t, f.ddb.counts)
}

func TestValidationExistingRecord(t *testing.T) {
	f := setup(t)
	f.r53.records[testWildcard] = testTarget
	f.r53.records[testName] = strings.TrimSuffix(testValue, ".")
	f.ddb.counts["account#"+testAccount] = 500
	delete(f.hosts, testTarget)

	code, result := post(t, request(t, "*."+testHost, testName, testValue))
	assert.Equal(t, 200, code)
	assert.Equal(t, testName+" "+testValue, result)

	f.r53.records[testName] = "_00000000000000000000000000000000.abcdefghij.acm-validations.aws."

	code, result = post(t, request(t, "*."+testHost, testName, testValue))
	assert.Equal(t, 409, code)
	assert.Equal(t, "record exists with a different value", result)

	assert.Empty(t, f.r53.batches)
	assert.Equal(t, 500, f.ddb.counts["account#"+testAccount])
}

func TestValidationRecordCap(t *testing.T) {
	f := setup(t)
	f.r53.records[testWildcard] = testTarget
	f.ddb.counts["account#"+testAccount] = 500

	code, result := post(t, request(t, "*."+testHost, testName, testValue))
	assert.Equal(t, 429, code)
	assert.Equal(t, "record limit reached", result)

	f.ddb.counts["account#"+testAccount] = 498

	code, result = post(t, request(t, "*."+serviceHost, serviceName, testValue))
	assert.Equal(t, 429, code)
	assert.Equal(t, "record limit reached", result)

	code, _ = post(t, request(t, "*."+testHost, testName, testValue))
	assert.Equal(t, 200, code)
	assert.Equal(t, 499, f.ddb.counts["account#"+testAccount])
	assert.Len(t, f.r53.batches, 1)
}

func TestValidationCreateFailure(t *testing.T) {
	f := setup(t)
	f.r53.records[testWildcard] = testTarget
	f.r53.create = func([]*route53.Change) error {
		return awserr.New("Throttling", "Rate exceeded", nil)
	}

	code, result := post(t, request(t, "*."+testHost, testName, testValue))
	assert.Equal(t, 503, code)
	assert.Equal(t, "registrar unavailable", result)
	assert.Equal(t, 0, f.ddb.counts["account#"+testAccount])

	f.r53.create = func([]*route53.Change) error {
		f.r53.records[testName] = testValue
		return awserr.New(route53.ErrCodeInvalidChangeBatch, "already exists", nil)
	}

	code, _ = post(t, request(t, "*."+testHost, testName, testValue))
	assert.Equal(t, 200, code)
	assert.Equal(t, 0, f.ddb.counts["account#"+testAccount])

	delete(f.r53.records, testName)
	f.r53.create = func([]*route53.Change) error {
		f.r53.records[testName] = "_00000000000000000000000000000000.abcdefghij.acm-validations.aws."
		return awserr.New(route53.ErrCodeInvalidChangeBatch, "already exists", nil)
	}

	code, result = post(t, request(t, "*."+testHost, testName, testValue))
	assert.Equal(t, 409, code)
	assert.Equal(t, "record exists with a different value", result)
	assert.Equal(t, 0, f.ddb.counts["account#"+testAccount])
}

func TestValidationRegisterFailure(t *testing.T) {
	f := setup(t)
	f.r53.create = func(changes []*route53.Change) error {
		if aws.StringValue(changes[0].ResourceRecordSet.Name) == testWildcard {
			return awserr.New("Throttling", "Rate exceeded", nil)
		}
		return nil
	}

	code, result := post(t, request(t, "*."+testHost, testName, testValue))
	assert.Equal(t, 503, code)
	assert.Equal(t, "registrar unavailable", result)
	assert.Empty(t, f.r53.batches)
	assert.NotContains(t, f.r53.records, testName)
	assert.Equal(t, 0, f.ddb.counts["account#"+testAccount])
	assert.Equal(t, testAccount, f.ddb.owners["lb#"+testSite])
}

func TestValidationDependencyFailure(t *testing.T) {
	f := setup(t)
	f.r53.records[testWildcard] = testTarget
	f.ddb.err = awserr.New("AccessDeniedException", "User: arn:aws:iam::111122223333:user/certbot is not authorized to perform: dynamodb:GetItem", nil)

	code, result := post(t, request(t, "*."+testHost, testName, testValue))
	assert.Equal(t, 503, code)
	assert.Equal(t, "registrar unavailable", result)
	assert.Empty(t, f.r53.batches)
}
