package authorization

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"

	"github.com/go-chi/chi"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/influxdata/httprouter"
	"github.com/influxdata/influxdb/v2"
	icontext "github.com/influxdata/influxdb/v2/context"
	"github.com/influxdata/influxdb/v2/inmem"
	"github.com/influxdata/influxdb/v2/kv"
	"github.com/influxdata/influxdb/v2/mock"
	itesting "github.com/influxdata/influxdb/v2/testing"
	"go.uber.org/zap/zaptest"
)

func NewTestInmemStore(t *testing.T) (kv.Store, func(), error) {
	return inmem.NewKVStore(), func() {}, nil
}

func TestService_handlePostAuthorization(t *testing.T) {
	type fields struct {
		AuthorizationService influxdb.AuthorizationService
		TenantService        TenantService
		LookupService        influxdb.LookupService
	}
	type args struct {
		session       *influxdb.Authorization
		authorization *influxdb.Authorization
	}
	type wants struct {
		statusCode  int
		contentType string
		body        string
	}

	tests := []struct {
		name   string
		fields fields
		args   args
		wants  wants
	}{
		{
			name: "create a new authorization",
			fields: fields{
				AuthorizationService: &mock.AuthorizationService{
					CreateAuthorizationFn: func(ctx context.Context, c *influxdb.Authorization) error {
						c.ID = itesting.MustIDBase16("020f755c3c082000")
						return nil
					},
				},
				TenantService: &tenantService{
					FindUserByIDFn: func(ctx context.Context, id influxdb.ID) (*influxdb.User, error) {
						return &influxdb.User{
							ID:   id,
							Name: "u1",
						}, nil
					},
					FindOrganizationByIDF: func(ctx context.Context, id influxdb.ID) (*influxdb.Organization, error) {
						return &influxdb.Organization{
							ID:   id,
							Name: "o1",
						}, nil
					},
				},
				LookupService: &mock.LookupService{
					NameFn: func(ctx context.Context, resource influxdb.ResourceType, id influxdb.ID) (string, error) {
						switch resource {
						case influxdb.BucketsResourceType:
							return "b1", nil
						case influxdb.OrgsResourceType:
							return "o1", nil
						}
						return "", fmt.Errorf("bad resource type %s", resource)
					},
				},
			},
			args: args{
				session: &influxdb.Authorization{
					Token:       "session-token",
					ID:          itesting.MustIDBase16("020f755c3c082000"),
					UserID:      itesting.MustIDBase16("aaaaaaaaaaaaaaaa"),
					OrgID:       itesting.MustIDBase16("020f755c3c083000"),
					Description: "can write to authorization resource",
					Permissions: []influxdb.Permission{
						{
							Action: influxdb.WriteAction,
							Resource: influxdb.Resource{
								Type:  influxdb.AuthorizationsResourceType,
								OrgID: itesting.IDPtr(itesting.MustIDBase16("020f755c3c083000")),
							},
						},
					},
				},
				authorization: &influxdb.Authorization{
					ID:          itesting.MustIDBase16("020f755c3c082000"),
					OrgID:       itesting.MustIDBase16("020f755c3c083000"),
					Description: "only read dashboards sucka",
					Permissions: []influxdb.Permission{
						{
							Action: influxdb.ReadAction,
							Resource: influxdb.Resource{
								Type:  influxdb.DashboardsResourceType,
								OrgID: itesting.IDPtr(itesting.MustIDBase16("020f755c3c083000")),
							},
						},
					},
				},
			},
			wants: wants{
				statusCode:  http.StatusCreated,
				contentType: "application/json; charset=utf-8",
				body: `
{
	"createdAt": "0001-01-01T00:00:00Z",
	"updatedAt": "0001-01-01T00:00:00Z",
  "description": "only read dashboards sucka",
  "id": "020f755c3c082000",
  "links": {
    "self": "/api/v2/authorizations/020f755c3c082000",
    "user": "/api/v2/users/aaaaaaaaaaaaaaaa"
  },
  "org": "o1",
  "orgID": "020f755c3c083000",
  "permissions": [
    {
      "action": "read",
			"resource": {
				"type": "dashboards",
				"orgID": "020f755c3c083000",
				"org": "o1"
			}
    }
  ],
  "status": "active",
  "token": "new-test-token",
  "user": "u1",
  "userID": "aaaaaaaaaaaaaaaa"
}
`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Helper()

			s, _, err := NewTestInmemStore(t)
			if err != nil {
				t.Fatal(err)
			}

			storage, err := NewStore(s)
			if err != nil {
				t.Fatal(err)
			}

			svc := NewService(storage, tt.fields.TenantService)

			handler := NewHTTPAuthHandler(zaptest.NewLogger(t), svc, tt.fields.TenantService, mock.NewLookupService())
			router := chi.NewRouter()
			router.Mount(handler.Prefix(), handler)

			req, err := newPostAuthorizationRequest(tt.args.authorization)
			if err != nil {
				t.Fatalf("failed to create new authorization request: %v", err)
			}
			b, err := json.Marshal(req)
			if err != nil {
				t.Fatalf("failed to unmarshal authorization: %v", err)
			}

			r := httptest.NewRequest("GET", "http://any.url", bytes.NewReader(b))
			r = r.WithContext(context.WithValue(
				context.Background(),
				httprouter.ParamsKey,
				httprouter.Params{
					{
						Key:   "userID",
						Value: string(tt.args.session.UserID),
					},
				}))

			w := httptest.NewRecorder()

			ctx := icontext.SetAuthorizer(context.Background(), tt.args.session)
			r = r.WithContext(ctx)

			handler.handlePostAuthorization(w, r)

			res := w.Result()
			content := res.Header.Get("Content-Type")
			body, _ := ioutil.ReadAll(res.Body)

			if res.StatusCode != tt.wants.statusCode {
				t.Logf("headers: %v body: %s", res.Header, body)
				t.Errorf("%q. handlePostAuthorization() = %v, want %v", tt.name, res.StatusCode, tt.wants.statusCode)
			}
			if tt.wants.contentType != "" && content != tt.wants.contentType {
				t.Errorf("%q. handlePostAuthorization() = %v, want %v", tt.name, content, tt.wants.contentType)
			}
			if diff, err := jsonDiff(string(body), tt.wants.body); err != nil {
				t.Errorf("%q, handlePostAuthorization(). error unmarshaling json %v", tt.name, err)
			} else if tt.wants.body != "" && diff != "" {
				t.Errorf("%q. handlePostAuthorization() = ***%s***", tt.name, diff)
			}
		})
	}
}

func jsonDiff(s1, s2 string) (diff string, err error) {
	if s1 == s2 {
		return "", nil
	}

	if s1 == "" {
		return s2, fmt.Errorf("s1 is empty")
	}

	if s2 == "" {
		return s1, fmt.Errorf("s2 is empty")
	}

	var o1 influxdb.Authorization
	if err = json.Unmarshal([]byte(s1), &o1); err != nil {
		return
	}

	var o2 influxdb.Authorization
	if err = json.Unmarshal([]byte(s2), &o2); err != nil {
		return
	}

	return cmp.Diff(o1, o2, authorizationCmpOptions...), err
}

var authorizationCmpOptions = cmp.Options{
	cmpopts.EquateEmpty(),
	cmpopts.IgnoreFields(influxdb.Authorization{}, "ID", "Token", "CreatedAt", "UpdatedAt"),
	cmp.Comparer(func(x, y []byte) bool {
		return bytes.Equal(x, y)
	}),
	cmp.Transformer("Sort", func(in []*influxdb.Authorization) []*influxdb.Authorization {
		out := append([]*influxdb.Authorization(nil), in...) // Copy input to avoid mutating it
		sort.Slice(out, func(i, j int) bool {
			return out[i].ID.String() > out[j].ID.String()
		})
		return out
	}),
}
