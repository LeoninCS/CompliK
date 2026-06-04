package commitment

import (
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"sealos-complik-admin/internal/modules/pagequery"
)

type Handler struct {
	service *Service
}

func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

// CreateOrUploadCommitment routes POST /api/commitments based on content type.
func (h *Handler) CreateOrUploadCommitment(c *gin.Context) {
	contentType := strings.ToLower(c.GetHeader("Content-Type"))
	if strings.HasPrefix(contentType, "multipart/form-data") {
		h.UploadCommitment(c)
		return
	}

	h.CreateCommitment(c)
}

// UploadCommitment handles uploading a commitment PDF and saving its metadata.
func (h *Handler) UploadCommitment(c *gin.Context) {
	var req UploadCommitmentRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "invalid form data",
			"error":   err.Error(),
		})

		return
	}

	fileHeader, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "missing pdf file",
			"error":   err.Error(),
		})

		return
	}

	resp, err := h.service.UploadCommitment(c.Request.Context(), req.Namespace, fileHeader)
	if err != nil {
		h.respondWithServiceError(c, err, "failed to upload commitment")
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "commitment uploaded successfully",
		"data":    resp,
	})
}

// CreateCommitment handles the creation of a new commitment.
func (h *Handler) CreateCommitment(c *gin.Context) {
	var req CreateCommitmentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "invalid request body",
			"error":   err.Error(),
		})

		return
	}

	if err := h.service.CreateCommitment(c.Request.Context(), req); err != nil {
		h.respondWithServiceError(c, err, "failed to create commitment")
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "commitment created successfully",
	})
}

// UpdateCommitment handles updating a commitment by namespace.
func (h *Handler) UpdateCommitment(c *gin.Context) {
	namespace, ok := bindCommitmentNamespace(c)
	if !ok {
		return
	}

	var req UpdateCommitmentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "invalid request body",
			"error":   err.Error(),
		})

		return
	}

	if err := h.service.UpdateCommitment(c.Request.Context(), namespace, req); err != nil {
		h.respondWithServiceError(c, err, "failed to update commitment")
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "commitment updated successfully",
	})
}

// DeleteCommitment handles deleting a commitment by namespace.
func (h *Handler) DeleteCommitment(c *gin.Context) {
	namespace, ok := bindCommitmentNamespace(c)
	if !ok {
		return
	}

	if err := h.service.DeleteCommitment(c.Request.Context(), namespace); err != nil {
		h.respondWithServiceError(c, err, "failed to delete commitment")
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "commitment deleted successfully",
	})
}

// GetCommitment handles retrieving a commitment by namespace.
func (h *Handler) GetCommitment(c *gin.Context) {
	namespace, ok := bindCommitmentNamespace(c)
	if !ok {
		return
	}

	resp, err := h.service.GetCommitment(c.Request.Context(), namespace)
	if err != nil {
		h.respondWithServiceError(c, err, "failed to get commitment")
		return
	}

	c.JSON(http.StatusOK, resp)
}

// ListCommitments handles listing all commitments.
func (h *Handler) ListCommitments(c *gin.Context) {
	if pagequery.HasPage(c.Query("page")) {
		h.ListCommitmentsPage(c)
		return
	}

	resp, err := h.service.ListCommitments(c.Request.Context())
	if err != nil {
		h.respondWithServiceError(c, err, "failed to list commitments")
		return
	}

	c.JSON(http.StatusOK, resp)
}

func (h *Handler) ListCommitmentsPage(c *gin.Context) {
	var req ListCommitmentsQueryRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "invalid request query",
			"error":   err.Error(),
		})

		return
	}

	options, err := pagequery.NewOptions(req.Page)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "invalid page query",
		})
		return
	}

	resp, err := h.service.ListCommitmentsPage(c.Request.Context(), options, req.Keyword)
	if err != nil {
		h.respondWithServiceError(c, err, "failed to list commitments")
		return
	}

	c.JSON(http.StatusOK, resp)
}

// DownloadCommitment downloads commitment file by namespace with attachment header.
func (h *Handler) DownloadCommitment(c *gin.Context) {
	namespace, ok := bindCommitmentNamespace(c)
	if !ok {
		return
	}

	file, err := h.service.DownloadCommitment(c.Request.Context(), namespace)
	if err != nil {
		h.respondWithServiceError(c, err, "failed to download commitment")
		return
	}

	defer func() {
		_ = file.Reader.Close()
	}()

	c.Header("Content-Type", file.ContentType)
	c.Header("Content-Disposition", "attachment; filename*=UTF-8''"+url.QueryEscape(file.FileName))
	c.Status(http.StatusOK)

	if _, err := io.Copy(c.Writer, file.Reader); err != nil {
		_ = c.Error(err)
	}
}

// bindCommitmentNamespace extracts the namespace from the URI and validates it.
func bindCommitmentNamespace(c *gin.Context) (string, bool) {
	var req CommitmentNamespaceRequest
	if err := c.ShouldBindUri(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "invalid request path",
			"error":   err.Error(),
		})

		return "", false
	}

	return req.Namespace, true
}

// respondWithServiceError handles responding with appropriate error messages based on the service error.
func (h *Handler) respondWithServiceError(c *gin.Context, err error, fallbackMessage string) {
	switch {
	case errors.Is(err, ErrCommitmentInvalidInput):
		c.JSON(http.StatusBadRequest, gin.H{
			"message": err.Error(),
		})
	case errors.Is(err, ErrCommitmentInvalidFile):
		c.JSON(http.StatusBadRequest, gin.H{
			"message": err.Error(),
		})
	case errors.Is(err, ErrCommitmentUploadDisabled):
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"message": err.Error(),
		})
	case errors.Is(err, ErrCommitmentAlreadyExists):
		c.JSON(http.StatusConflict, gin.H{
			"message": err.Error(),
		})
	case errors.Is(err, ErrCommitmentNotFound):
		c.JSON(http.StatusNotFound, gin.H{
			"message": err.Error(),
		})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": fallbackMessage,
			"error":   err.Error(),
		})
	}
}
