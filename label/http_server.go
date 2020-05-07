package label

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/influxdata/influxdb/v2"
	kithttp "github.com/influxdata/influxdb/v2/kit/transport/http"
	"go.uber.org/zap"
)

type LabelHandler struct {
	chi.Router
	api      *kithttp.API
	log      *zap.Logger
	labelSvc influxdb.LabelService
}

const (
	prefixLabels = "/api/v2/labels"
)

func (h *LabelHandler) Prefix() string {
	return prefixLabels
}

func NewHTTPLabelHandler(log *zap.Logger, ls influxdb.LabelService) *LabelHandler {
	h := &LabelHandler{
		api:      kithttp.NewAPI(kithttp.WithLog(log)),
		log:      log,
		labelSvc: ls,
	}

	r := chi.NewRouter()
	r.Use(
		middleware.Recoverer,
		middleware.RequestID,
		middleware.RealIP,
	)

	r.Route("/", func(r chi.Router) {
		r.Post("/", h.handlePostLabel)
		r.Get("/", h.handleGetLabel)

		r.Route("/{id}", func(r chi.Router) {
			r.Get("/", h.handleGetLabel)
			r.Patch("/", h.handlePatchLabel)
			r.Delete("/", h.handleDeleteLabel)
		})
	})

	h.Router = r
	return h
}

type labelResponse struct {
	Links map[string]string `json:"links"`
	Label influxdb.Label    `json:"label"`
}

func newLabelResponse(l *influxdb.Label) *labelResponse {
	return &labelResponse{
		Links: map[string]string{
			"self": fmt.Sprintf("/api/v2/labels/%s", l.ID),
		},
		Label: *l,
	}
}

type labelsResponse struct {
	Links  map[string]string `json:"links"`
	Labels []*influxdb.Label `json:"labels"`
}

func newLabelsResponse(ls []*influxdb.Label) *labelsResponse {
	return &labelsResponse{
		Links: map[string]string{
			"self": fmt.Sprintf("/api/v2/labels"),
		},
		Labels: ls,
	}
}

// handlePostLabel is the HTTP handler for the POST /api/v2/labels route.
func (h *LabelHandler) handlePostLabel(w http.ResponseWriter, r *http.Request) {
	var label influxdb.Label
	if err := h.api.DecodeJSON(r.Body, &label); err != nil {
		h.api.Err(w, err)
		return
	}

	// TODO(al): ensure that the specified org actually exists
	// can be done in service

	if err := h.labelSvc.CreateLabel(r.Context(), &label); err != nil {
		h.api.Err(w, err)
		return
	}
	h.log.Debug("Label created", zap.String("label", fmt.Sprint(label)))
	// todo (al) add logging to middleware

	h.api.Respond(w, http.StatusCreated, newLabelResponse(&label))
}

type postLabelRequest struct {
	Label *influxdb.Label
}

func (b postLabelRequest) Validate() error {
	if b.Label.Name == "" {
		return &influxdb.Error{
			Code: influxdb.EInvalid,
			Msg:  "label requires a name",
		}
	}
	if !b.Label.OrgID.Valid() {
		return &influxdb.Error{
			Code: influxdb.EInvalid,
			Msg:  "label requires a valid orgID",
		}
	}
	return nil
}

// handleGetLabel is the HTTP handler for the GET /api/v2/labels/id route.
func (h *LabelHandler) handleGetLabel(w http.ResponseWriter, r *http.Request) {
	id, err := influxdb.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		h.api.Err(w, err)
		return
	} // old message label is not valid

	l, err := h.labelSvc.FindLabelByID(r.Context(), *id)
	if err != nil {
		h.api.Err(w, err)
		return
	}
	h.log.Debug("Label retrieved", zap.String("label", fmt.Sprint(l)))

	h.api.Respond(w, http.StatusOK, newLabelResponse(l))
}

type getLabelRequest struct {
	LabelID influxdb.ID
}

// handleGetLabels is the HTTP handler for the GET /api/v2/labels route.
func (h *LabelHandler) handleGetLabels(w http.ResponseWriter, r *http.Request) {
	var filter influxdb.LabelFilter
	qp := r.URL.Query()

	if name := qp.Get("name"); name != "" {
		filter.Name = name
	}

	if orgID := qp.Get("orgID"); orgID != "" {
		i, err := influxdb.IDFromString(orgID)
		if err == nil {
			filter.OrgID = i
		}
	}

	labels, err := h.labelSvc.FindLabels(r.Context(), filter)
	if err != nil {
		h.api.Err(w, err)
		return
	}
	h.log.Debug("Labels retrived", zap.String("labels", fmt.Sprint(labels)))

	h.api.Respond(w, http.StatusOK, newLabelsResponse(labels))
}

// handlePatchLabel is the HTTP handler for the PATCH /api/v2/labels route.
func (h *LabelHandler) handlePatchLabel(w http.ResponseWriter, r *http.Request) {
	id, err := influxdb.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		h.api.Err(w, err)
		return
	}

	upd := &influxdb.LabelUpdate{}
	if err := json.NewDecoder(r.Body).Decode(upd); err != nil {
		h.api.Err(w, err)
		return
	}

	l, err := h.labelSvc.UpdateLabel(r.Context(), *id, *upd)
	if err != nil {
		h.api.Err(w, err)
		return
	}
	h.log.Debug("Label updated", zap.String("label", fmt.Sprint(l)))

	h.api.Respond(w, http.StatusOK, newLabelResponse(l))
}

// handleDeleteLabel is the HTTP handler for the DELETE /api/v2/labels/:id route.
func (h *LabelHandler) handleDeleteLabel(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, err := influxdb.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		h.api.Err(w, err)
		return
	}
	if err := h.labelSvc.DeleteLabel(ctx, *id); err != nil {
		h.api.Err(w, err)
		return
	}
	h.log.Debug("Label deleted", zap.String("labelID", fmt.Sprint(id)))

	h.api.Respond(w, http.StatusNoContent, nil)
}
