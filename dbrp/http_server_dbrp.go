package dbrp

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi"
	"github.com/influxdata/influxdb/v2"
	kithttp "github.com/influxdata/influxdb/v2/kit/transport/http"
	"go.uber.org/zap"
)

const (
	prefixDBRP = "/api/v2/dbrps"
)

type Handler struct {
	chi.Router
	api     *kithttp.API
	log     *zap.Logger
	dbrpSvc influxdb.DBRPMappingServiceV2
}

// NewHTTPHandler constructs a new http server.
func NewHTTPHandler(log *zap.Logger, dbrpSvc influxdb.DBRPMappingServiceV2) *Handler {
	h := &Handler{
		api:     kithttp.NewAPI(kithttp.WithLog(log)),
		log:     log,
		dbrpSvc: dbrpSvc,
	}

	r := chi.NewRouter()

	r.Route("/", func(r chi.Router) {
		r.Post("/", h.handlePostDBRP)
		r.Get("/", h.handleGetDBRPs)

		r.Route("/{id}", func(r chi.Router) {
			r.Get("/", h.handleGetDBRP)
			r.Patch("/", h.handlePatchDBRP)
			r.Delete("/", h.handleDeleteDBRP)
		})
	})

	h.Router = r
	return h
}

type createDBRPRequest struct {
	Database        string      `json:"database"`
	RetentionPolicy string      `json:"retention_policy"`
	Default         bool        `json:"default"`
	OrganizationID  influxdb.ID `json:"organization_id"`
	BucketID        influxdb.ID `json:"bucket_id"`
}

func (h *Handler) handlePostDBRP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req createDBRPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.api.Err(w, &influxdb.Error{
			Code: influxdb.EInvalid,
			Msg:  "invalid json structure",
			Err:  err,
		})
		return
	}

	dbrp := &influxdb.DBRPMappingV2{
		Database:        req.Database,
		RetentionPolicy: req.RetentionPolicy,
		Default:         req.Default,
		OrganizationID:  req.OrganizationID,
		BucketID:        req.BucketID,
	}
	if err := h.dbrpSvc.Create(ctx, dbrp); err != nil {
		h.api.Err(w, err)
		return
	}
	h.api.Respond(w, http.StatusCreated, dbrp)
}

type getDBRPsResponse struct {
	Content []*influxdb.DBRPMappingV2 `json:"content"`
}

func (h *Handler) handleGetDBRPs(w http.ResponseWriter, r *http.Request) {
	filter := influxdb.DBRPMappingFilterV2{}

	filter, err := getFilterFromHTTPRequest(r)
	if err != nil {
		h.api.Err(w, err)
		return
	}
	dbrps, _, err := h.dbrpSvc.FindMany(r.Context(), filter)
	if err != nil {
		h.api.Err(w, err)
		return
	}

	h.api.Respond(w, http.StatusOK, getDBRPsResponse{
		Content: dbrps,
	})
}

type getDBRPResponse struct {
	Content *influxdb.DBRPMappingV2 `json:"content"`
}

func (h *Handler) handleGetDBRP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")
	if id == "" {
		h.api.Err(w, &influxdb.Error{
			Code: influxdb.EInvalid,
			Msg:  "url missing id",
		})
		return
	}

	var i influxdb.ID
	if err := i.DecodeFromString(id); err != nil {
		h.api.Err(w, err)
		return
	}

	orgID, err := mustGetOrgIDFromHTTPRequest(r)
	if err != nil {
		h.api.Err(w, err)
		return
	}

	dbrp, err := h.dbrpSvc.FindByID(ctx, *orgID, i)
	if err != nil {
		h.api.Err(w, err)
		return
	}
	h.api.Respond(w, http.StatusOK, getDBRPResponse{
		Content: dbrp,
	})
}

func (h *Handler) handlePatchDBRP(w http.ResponseWriter, r *http.Request) {
	bodyRequest := struct {
		Default         *bool   `json:"default"`
		RetentionPolicy *string `json:"retention_policy"`
		Database        *string `json:"database"`
	}{}

	ctx := r.Context()

	id := chi.URLParam(r, "id")
	if id == "" {
		h.api.Err(w, &influxdb.Error{
			Code: influxdb.EInvalid,
			Msg:  "url missing id",
		})
		return
	}

	var i influxdb.ID
	if err := i.DecodeFromString(id); err != nil {
		h.api.Err(w, err)
		return
	}

	orgID, err := mustGetOrgIDFromHTTPRequest(r)
	if err != nil {
		h.api.Err(w, err)
		return
	}

	dbrp, err := h.dbrpSvc.FindByID(ctx, *orgID, i)
	if err != nil {
		h.api.Err(w, err)
		return
	}

	if err := json.NewDecoder(r.Body).Decode(&bodyRequest); err != nil {
		h.api.Err(w, &influxdb.Error{
			Code: influxdb.EInvalid,
			Msg:  "invalid json structure",
			Err:  err,
		})
		return
	}

	if bodyRequest.Default != nil && dbrp.Default != *bodyRequest.Default {
		dbrp.Default = *bodyRequest.Default
	}

	if bodyRequest.Database != nil && *bodyRequest.Database != dbrp.Database {
		dbrp.Database = *bodyRequest.Database
	}

	if bodyRequest.RetentionPolicy != nil && *bodyRequest.RetentionPolicy != dbrp.RetentionPolicy {
		dbrp.RetentionPolicy = *bodyRequest.RetentionPolicy
	}

	if err := h.dbrpSvc.Update(ctx, dbrp); err != nil {
		h.api.Err(w, err)
		return
	}

	h.api.Respond(w, http.StatusOK, struct {
		Content *influxdb.DBRPMappingV2 `json:"content"`
	}{
		Content: dbrp,
	})
}

func (h *Handler) handleDeleteDBRP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")
	if id == "" {
		h.api.Err(w, &influxdb.Error{
			Code: influxdb.EInvalid,
			Msg:  "url missing id",
		})
		return
	}

	var i influxdb.ID
	if err := i.DecodeFromString(id); err != nil {
		h.api.Err(w, err)
		return
	}

	orgID, err := mustGetOrgIDFromHTTPRequest(r)
	if err != nil {
		h.api.Err(w, err)
		return
	}

	if err := h.dbrpSvc.Delete(ctx, *orgID, i); err != nil {
		h.api.Err(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func getFilterFromHTTPRequest(r *http.Request) (f influxdb.DBRPMappingFilterV2, err error) {
	// Always provide OrgID.
	f.OrgID, err = mustGetOrgIDFromHTTPRequest(r)
	if err != nil {
		return f, err
	}
	f.ID, err = getDBRPIDFromHTTPRequest(r)
	if err != nil {
		return f, err
	}
	f.BucketID, err = getBucketIDFromHTTPRequest(r)
	if err != nil {
		return f, err
	}
	rawDB := r.URL.Query().Get("db")
	if rawDB != "" {
		f.Database = &rawDB
	}
	rawRP := r.URL.Query().Get("rp")
	if rawRP != "" {
		f.RetentionPolicy = &rawRP
	}
	rawDefault := r.URL.Query().Get("default")
	if rawDefault != "" {
		d, err := strconv.ParseBool(rawDefault)
		if err != nil {
			return f, &influxdb.Error{
				Code: influxdb.EInvalid,
				Msg:  "invalid default parameter",
			}
		}
		f.Default = &d
	}
	return f, nil
}

func getIDFromHTTPRequest(r *http.Request, key string) (*influxdb.ID, error) {
	var id influxdb.ID
	raw := r.URL.Query().Get(key)
	if raw != "" {
		if err := id.DecodeFromString(raw); err != nil {
			return nil, influxdb.ErrInvalidID
		}
	} else {
		return nil, nil
	}
	return &id, nil
}

func mustGetOrgIDFromHTTPRequest(r *http.Request) (*influxdb.ID, error) {
	orgID, err := getIDFromHTTPRequest(r, "orgID")
	if err != nil {
		return nil, err
	}
	if orgID == nil {
		return nil, influxdb.ErrOrgNotFound
	}
	return orgID, nil
}

func getDBRPIDFromHTTPRequest(r *http.Request) (*influxdb.ID, error) {
	return getIDFromHTTPRequest(r, "id")
}

func getBucketIDFromHTTPRequest(r *http.Request) (*influxdb.ID, error) {
	return getIDFromHTTPRequest(r, "bucketID")
}
