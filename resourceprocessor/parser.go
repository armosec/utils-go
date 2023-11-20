package resourceprocessor

import (
	"time"

	"github.com/armosec/utils-k8s-go/armometadata"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	AnnotationKeyStatus       = "kubescape.io/status"
	AnnotationValueIncomplete = "incomplete"

	MetadataKeyResourceVersion = "resourceVersion"
)

type KubernetesObjectParser struct {
	resourceVersion string
	labels          map[string]string
	annotations     map[string]string
	creationStamp   time.Time
	ownerReferences metav1.OwnerReference
}

func NewKubernetesResourceParser(input []byte) (*KubernetesObjectParser, error) {
	err, annotations, labels, ownerReferences, creationStamp, resourceVersion := armometadata.ExtractMetadataFromJsonBytes(input)

	if err != nil {
		return nil, err
	}

	creationStampTime, err := time.Parse(time.RFC3339, creationStamp)
	if err != nil {
		return nil, err
	}

	newOwnerReferences := metav1.OwnerReference{}

	if len(ownerReferences) > 0 {
		if value, ok := ownerReferences["name"]; ok {
			newOwnerReferences.Name = value
		}

		if value, ok := ownerReferences["kind"]; ok {
			newOwnerReferences.Kind = value
		}

	}

	newKubernetesResourceParser := &KubernetesObjectParser{}
	newKubernetesResourceParser.resourceVersion = resourceVersion
	newKubernetesResourceParser.labels = labels
	newKubernetesResourceParser.annotations = annotations
	newKubernetesResourceParser.creationStamp = creationStampTime
	newKubernetesResourceParser.ownerReferences = newOwnerReferences

	return newKubernetesResourceParser, nil
}

func (k *KubernetesObjectParser) GetLabel(label string) string {
	return k.labels[label]
}

func (k *KubernetesObjectParser) GetAnnotation(annotation string) string {
	return k.annotations[annotation]
}

func (k *KubernetesObjectParser) GetCreationTimestamp() time.Time {
	return k.creationStamp
}

func (k *KubernetesObjectParser) GetResourceVersion() string {
	return k.resourceVersion
}

func (k *KubernetesObjectParser) GetOwnerReferencesKind() string {
	return k.ownerReferences.Kind
}

func (k *KubernetesObjectParser) GetOwnerReferencesName() string {
	return k.ownerReferences.Name
}

func (k *KubernetesObjectParser) GetStatus() string {
	return k.annotations[AnnotationKeyStatus]
}
