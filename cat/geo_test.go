package cat_test

import (
	"testing"

	"github.com/terra-howard/wtcat/cat"
	"github.com/terra-howard/wtcat/cwt"
)

func located(country, region string) *cat.Request {
	req := get()
	req.Location = &cat.Location{Country: country, Region: region}
	return req
}

func TestCatgeoiso3166(t *testing.T) {
	token := claimsToken(t, map[any]any{316: []string{"CA-ON", "US"}})
	cases := []struct {
		name string
		req  *cat.Request
		want error
	}{
		{"a listed country", located("US", "TX"), nil},
		{"a listed region", located("CA", "ON"), nil},
		{"a listed country, given in lowercase", located("us", ""), nil},
		{"an unlisted region of a country listed by region", located("CA", "QC"), cat.ErrLocation},
		{"an unlisted country", located("FR", ""), cat.ErrLocation},
		{"a client that could not be located", located("", ""), cat.ErrLocation},
		{"a recipient that does not locate clients", get(), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := validator().ValidateRequest(token, tc.req)
			if tc.want == nil {
				if err != nil {
					t.Fatalf("ValidateRequest: %v", err)
				}
				return
			}
			wantKind(t, err, tc.want)
			wantKind(t, err, cat.ErrUnacceptable)
		})
	}
}

func TestCatgeoiso3166Syntax(t *testing.T) {
	for _, entry := range []string{"ca", "CAN", "C", "CA-", "CA-ABCD", "CA_ON", "CA-on"} {
		_, err := validator().ValidateRequest(claimsToken(t, map[any]any{316: []string{entry}}), located("CA", "ON"))
		wantKind(t, err, cwt.ErrMalformed)
	}
	for _, entry := range []string{"CA", "CA-ON", "GB-ENG", "FR-75"} {
		if _, err := validator().ValidateRequest(claimsToken(t, map[any]any{316: []string{entry}}), get()); err != nil {
			t.Errorf("%q: %v", entry, err)
		}
	}
}
