package resourceprocessor

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/identifiers"
	s3connector "github.com/armosec/utils-go/s3connector"
	instanceidhandler "github.com/kubescape/k8s-interface/instanceidhandler/v1"
	postgresconnectordal "github.com/kubescape/postgres-connector/dal"
	syncUtils "github.com/kubescape/synchronizer/utils"
	"go.uber.org/zap"
)

const (
	kubernetesResourcesS3KeyPrefix = "kubernetesresources"
)

type KubernetesResourceProcessor struct {
	pgDal     *postgresconnectordal.PostgresDAL
	s3Storage s3connector.ObjectStorage
}

func NewKubernetesResourceProcessor(s3Storage s3connector.ObjectStorage, pgDal *postgresconnectordal.PostgresDAL) *KubernetesResourceProcessor {
	return &KubernetesResourceProcessor{
		pgDal:     pgDal,
		s3Storage: s3Storage,
	}
}

// Delete deletes the resource from S3 and Postgres
// if deleting from S3 fails, the resource will not be deleted from Postgres
func (k KubernetesResourceProcessor) Delete(customerGUID, cluster, kind, namespace, name string) error {

	// delete from postgres and get object ref
	resourceObjectRef, err := k.deleteObjectFromPostgres(customerGUID, cluster, kind, namespace, name)
	if err != nil {
		return fmt.Errorf("deleteResource: failed to delete resource from postgres: %w", err)
	}

	objPath := s3connector.S3ObjectPath{}
	if err := json.Unmarshal([]byte(resourceObjectRef), &objPath); err != nil {
		return fmt.Errorf("failed to unmarshal object ref: %w", err)
	}

	// delete from s3
	// TODO : decide if we want to delete S3 objects on run-time or periodically against postgres reources current states

	// if err = k.s3Storage.DeleteObject(objPath); err != nil {

	// 	// failing to delete from s3 is not a critical error as postgres is the main source of truth for the resource
	// 	zap.L().Warn("failed to delete resource from s3", zap.Error(err))
	// }

	return nil

}

// Patch patches the resource in S3 and Postgres
// if patching in S3 fails, the resource will not be patched in Postgres
func (k KubernetesResourceProcessor) Patch(customerGUID, cluster, kind, namespace, name string, payload []byte) error {
	if payload == nil {
		return fmt.Errorf("In Patch: Payload is nil")
	}

	parser, err := NewKubernetesResourceParser(payload)

	if err != nil {
		return fmt.Errorf("In Patch: failed to parse resource: %w", err)
	}

	if parser.GetStatus() == AnnotationValueIncomplete {
		zap.L().Warn("In Patch: resource status is incomplete, skipping processing")
		return nil
	}

	key := generateResourceStorageKey(customerGUID, cluster, kind, namespace, name)

	objPath := s3connector.S3ObjectPath{
		Key: key,
	}

	objPath, err = k.s3Storage.StoreObject(objPath, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("In Patch: failed to store resource in s3: %w", err)
	}

	objRefBytes, err := json.Marshal(objPath)
	if err != nil {
		return fmt.Errorf("In Patch: failed to marshal object reference: %w", err)
	}

	checksum, err := syncUtils.CanonicalHash(payload)
	if err != nil {
		return fmt.Errorf("In Patch: failed to calculate checksum: %w", err)
	}

	resource := armotypes.KubernetesObject{
		Designators: identifiers.PortalDesignator{
			Attributes: map[string]string{
				identifiers.AttributeCluster:      cluster,
				identifiers.AttributeKind:         kind,
				identifiers.AttributeNamespace:    namespace,
				identifiers.AttributeName:         name,
				identifiers.AttributeCustomerGUID: customerGUID,
			},
		},
		ResourceVersion:    parser.GetResourceVersion(),
		CreationTimestamp:  parser.GetCreationTimestamp(),
		OwnerReferenceName: parser.GetOwnerReferencesName(),
		OwnerReferenceKind: parser.GetOwnerReferencesKind(),
		RelatedName:        parser.GetLabel(instanceidhandler.NameMetadataKey),
		RelatedKind:        parser.GetLabel(instanceidhandler.KindMetadataKey),
		RelatedNamespace:   parser.GetLabel(instanceidhandler.NamespaceMetadataKey),
		RelatedAPIGroup:    parser.GetLabel(instanceidhandler.ApiGroupMetadataKey),
		RelatedAPIVersion:  parser.GetLabel(instanceidhandler.ApiVersionMetadataKey),
		Checksum:           checksum,
		ResourceObjectRef:  string(objRefBytes),
	}

	return k.patchObjectInPostgres(resource)

}

// Store stores the resource in S3 and Postgres
// if storing in S3 fails, the resource will not be stored in Postgres
func (k KubernetesResourceProcessor) Store(customerGUID, cluster, kind, namespace, name string, payload []byte) error {
	if payload == nil {
		return fmt.Errorf("In Store: Payload is nil")
	}

	parser, err := NewKubernetesResourceParser(payload)

	if err != nil {
		return fmt.Errorf("In Store: failed to extract metadata from json bytes: %w", err)
	}

	if parser.GetStatus() == AnnotationValueIncomplete {
		zap.L().Warn("In Store: resource status is incomplete, skipping processing")
		return nil
	}

	key := generateResourceStorageKey(customerGUID, cluster, kind, namespace, name)
	objPath := s3connector.S3ObjectPath{
		Key: key,
	}
	objPath, err = k.s3Storage.StoreObject(objPath, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("In Store: failed to store resource in s3: %w", err)
	}

	objRefBytes, err := json.Marshal(objPath)
	if err != nil {
		return fmt.Errorf("In Store: failed to marshal object reference: %w", err)
	}

	checksum, err := syncUtils.CanonicalHash(payload)
	if err != nil {
		return fmt.Errorf("In Store: failed to calculate checksum: %w", err)
	}

	resource := armotypes.KubernetesObject{
		Designators: identifiers.PortalDesignator{
			Attributes: map[string]string{
				identifiers.AttributeCluster:      cluster,
				identifiers.AttributeKind:         kind,
				identifiers.AttributeNamespace:    namespace,
				identifiers.AttributeName:         name,
				identifiers.AttributeCustomerGUID: customerGUID,
			},
		},
		ResourceVersion:    parser.GetResourceVersion(),
		CreationTimestamp:  parser.GetCreationTimestamp(),
		OwnerReferenceName: parser.GetOwnerReferencesName(),
		OwnerReferenceKind: parser.GetOwnerReferencesKind(),
		RelatedName:        parser.GetLabel(instanceidhandler.NameMetadataKey),
		RelatedKind:        parser.GetLabel(instanceidhandler.KindMetadataKey),
		RelatedNamespace:   parser.GetLabel(instanceidhandler.NamespaceMetadataKey),
		RelatedAPIGroup:    parser.GetLabel(instanceidhandler.ApiGroupMetadataKey),
		RelatedAPIVersion:  parser.GetLabel(instanceidhandler.ApiVersionMetadataKey),
		Checksum:           checksum,
		ResourceObjectRef:  string(objRefBytes),
	}

	return k.storeObjectInPostgres(resource)
}

// Get gets the resource from S3 and Postgres
func (k KubernetesResourceProcessor) Get(customerGUID, cluster, kind, namespace, name string) (*armotypes.KubernetesObject, []byte, error) {

	resourceObject, found, err := k.GetObjectFromPostgres(customerGUID, cluster, kind, namespace, name)
	if err != nil {
		return nil, nil, fmt.Errorf("In Get: failed to get resource from postgres: %w", err)
	}

	if !found || resourceObject == nil {
		return nil, nil, nil
	}

	objPath := s3connector.S3ObjectPath{}
	if err := json.Unmarshal([]byte(resourceObject.ResourceObjectRef), &objPath); err != nil {
		return nil, nil, fmt.Errorf("In Get: failed to unmarshal object reference: %w", err)
	}

	objectBytes, err := k.GetObjectFromS3(objPath)

	if err != nil {
		return nil, nil, fmt.Errorf("In Get: failed to get resource from s3: %w", err)
	}

	return resourceObject, objectBytes, nil
}

// GetObjectFromPostgres gets the resource from Postgres
func (k KubernetesResourceProcessor) GetObjectFromPostgres(customerGUID, cluster, kind, namespace, name string) (*armotypes.KubernetesObject, bool, error) {
	resource, err := k.pgDal.RetrieveKubernetesObject(customerGUID, map[string]string{
		identifiers.AttributeCluster:   cluster,
		identifiers.AttributeKind:      kind,
		identifiers.AttributeNamespace: namespace,
		identifiers.AttributeName:      name,
	})

	if err != nil {
		return nil, false, err
	}

	if resource == nil {
		return nil, false, nil
	}

	return resource, true, nil
}

// GetObjectFromS3 gets the resource from S3
func (k KubernetesResourceProcessor) GetObjectFromS3(objPath s3connector.S3ObjectPath) ([]byte, error) {

	reader, err := k.s3Storage.GetObject(objPath)
	if err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(reader)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (k KubernetesResourceProcessor) patchObjectInPostgres(resource armotypes.KubernetesObject) error {
	err := k.pgDal.PatchKubernetesResource(resource.Designators.Attributes[identifiers.AttributeCustomerGUID], resource)
	if err != nil {
		return fmt.Errorf("patchObjectInPostgres: failed to patch resource in postgres: %w", err)
	}
	return nil
}

func (k KubernetesResourceProcessor) storeObjectInPostgres(resource armotypes.KubernetesObject) error {
	err := k.pgDal.StoreKubernetesResource(resource.Designators.Attributes[identifiers.AttributeCustomerGUID], resource)
	if err != nil {
		return fmt.Errorf("storeObjectInPostgres: failed to store resource in postgres: %w", err)
	}
	return nil
}

func (k KubernetesResourceProcessor) deleteObjectFromPostgres(customerGUID, cluster, kind, namespace, name string) (string, error) {
	resourceObjectRef, err := k.pgDal.DeleteKubernetesResource(customerGUID, map[string]string{
		identifiers.AttributeCluster:   cluster,
		identifiers.AttributeKind:      kind,
		identifiers.AttributeNamespace: namespace,
		identifiers.AttributeName:      name,
	})

	if err != nil {
		return "", err
	}
	return resourceObjectRef, nil
}

func generateResourceStorageKey(customerGUID, cluster, kind, namespace, name string) string {
	return fmt.Sprintf("%s/%s/%s/%s/%s/%s", kubernetesResourcesS3KeyPrefix, customerGUID, cluster, kind, namespace, name)
}
