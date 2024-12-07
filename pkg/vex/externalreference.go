package vex

import (
	"bytes"
	"fmt"
	"github.com/aquasecurity/trivy/pkg/sbom/core"
	"io"
	"net/http"
	"net/url"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
)

type ExternalReference struct{}

func NewExternalReference(report *types.Report) (VEX, error) {
	if report.ArtifactType != artifact.TypeCycloneDX {
		return nil, xerrors.Errorf("externalReferences can only be used when scanning CycloneDX SBOMs: %w", report.ArtifactType)
	}

	var externalRefs = report.BOM.ExternalReferences()
	var vexUrls []*url.URL

	for _, ref := range externalRefs {
		if ref.Type == core.ExternalReferenceVex {
			val, err := url.Parse(ref.URL)
			// do not concern ourselves with relative URLs
			if err != nil && val.Scheme != "https" && val.Scheme != "http" {
				continue
			}
			vexUrls = append(vexUrls, val)
		}
	}

	v, err := RetrieveExternalVEXDocuments(vexUrls, report)
	if err != nil {
		return nil, xerrors.Errorf("failed to fetch external VEX document: %w", err)
	}
	return v, nil
}

func RetrieveExternalVEXDocuments(urls []*url.URL, report *types.Report) (VEX, error) {

	logger := log.WithPrefix("vex").With(log.String("type", "externalReference"))

	// TODO this is inefficient - we are retrieving and parsing all documents even though
	// we throw them all away except the first one
	var VEXDocuments []VEX
	for i := range urls {
		VEXDocument, err := RetrieveExternalVEXDocument(urls[i], report)
		if err != nil {
			xerrors.Errorf("failed to retrieve external VEX document from URL: %w", err)
		} else {
			VEXDocuments = append(VEXDocuments, VEXDocument)
		}
		logger.Debug("Retrieved external VEX documents", "count", len(VEXDocuments))
	}
	if len(VEXDocuments) == 0 {
		logger.Info("No external VEX documents found")
		return nil, nil
	}
	logger.Debug("External VEX documents found, taking the first one")
	return VEXDocuments[0], nil

}

func RetrieveExternalVEXDocument(VEXUrl *url.URL, report *types.Report) (VEX, error) {

	logger := log.WithPrefix("vex").With(log.String("type", "externalReference"))

	logger.Info(fmt.Sprintf("Retrieving external VEX document from host %s", VEXUrl.Host))

	res, err := http.Get(VEXUrl.String())
	if err != nil {
		return nil, xerrors.Errorf("unable to fetch file via HTTP: %w", err)
	}
	defer res.Body.Close()

	val, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, xerrors.Errorf("unable to read response into memory: %w", err)
	}

	if v, err := decodeVEX(bytes.NewReader(val), VEXUrl.String(), report); err != nil {
		return nil, xerrors.Errorf("unable to load VEX: %w", err)
	} else {
		return v, nil
	}
}
