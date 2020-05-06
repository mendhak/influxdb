package dbrp

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/influxdata/influxdb/v2"
	kithttp "github.com/influxdata/influxdb/v2/kit/transport/http"
	"go.uber.org/zap"
)

type DBRPHandler struct {
	chi.Router
	api     *kithttp.API
	log     *zap.Logger
	dbrpSvc influxdb.DBRPMappingServiceV2
}

// NewHTTPAuthHandler constructs a new http server.
func NewHTTPDBRPHandler(log *zap.Logger, dbrpSvc influxdb.DBRPMappingServiceV2) *DBRPHandler {
	h := &DBRPHandler{
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

func (h *DBRPHandler) handlePostDBRP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	dbrp := &influxdb.DBRPMappingV2{}

	if err := json.NewDecoder(r.Body).Decode(dbrp); err != nil {
		h.api.Err(w, &influxdb.Error{
			Code: influxdb.EInvalid,
			Msg:  "invalid json structure",
			Err:  err,
		})
		return
	}

	if err := h.dbrpSvc.Create(ctx, dbrp); err != nil {
		h.api.Err(w, err)
		return
	}
	h.api.Respond(w, http.StatusCreated, dbrp)
}

func (h *DBRPHandler) handleGetDBRPs(w http.ResponseWriter, r *http.Request) {
	filter := influxdb.DBRPMappingFilterV2{}

	orgID, err := getOrgIDFromHTTPRequest(r)
	if err != nil {
		h.api.Err(w, err)
		return
	}

	filter.OrgID = &orgID

	dbrps, _, err := h.dbrpSvc.FindMany(r.Context(), filter)
	if err != nil {
		h.api.Err(w, err)
		return
	}

	h.api.Respond(w, http.StatusOK, struct {
		Content []*influxdb.DBRPMappingV2 `json:"content"`
	}{
		Content: dbrps,
	})
}

func (h *DBRPHandler) handleGetDBRP(w http.ResponseWriter, r *http.Request) {
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

	dbrp, err := h.dbrpSvc.FindByID(ctx, i)
	if err != nil {
		h.api.Err(w, err)
		return
	}
	h.api.Respond(w, http.StatusOK, struct {
		Content *influxdb.DBRPMappingV2 `json:"content"`
	}{
		Content: dbrp,
	})
}

func (h *DBRPHandler) handlePatchDBRP(w http.ResponseWriter, r *http.Request) {
	bodyRequest := &struct {
		Default         *bool   `json:"content"`
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

	dbrp, err := h.dbrpSvc.FindByID(ctx, i)
	if err != nil {
		h.api.Err(w, err)
		return
	}

	if err := json.NewDecoder(r.Body).Decode(bodyRequest); err != nil {
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

func (h *DBRPHandler) handleDeleteDBRP(w http.ResponseWriter, r *http.Request) {
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

	if err := h.dbrpSvc.Delete(ctx, i); err != nil {
		h.api.Err(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func getOrgIDFromHTTPRequest(r *http.Request) (influxdb.ID, error) {
	var orgID influxdb.ID
	orgIDraw := r.URL.Query().Get("orgID")
	if orgIDraw != "" {
		if err := orgID.DecodeFromString(orgIDraw); err != nil {
			return 0, influxdb.ErrInvalidID
		}
	} else {
		return 0, influxdb.ErrOrgNotFound
	}
	return orgID, nil
}
