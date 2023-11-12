package s3connector

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/cakturk/go-netstat/netstat"
)

//go:embed scripts/localstack.sh
var startLocalStackScript string

//go:embed scripts/localstack_stop.sh
var localStackStopCommand string

//go:embed scripts/localstack_print_logs.sh
var printLocalStackLogsCommand string

type S3LocalStack struct {
	endPointPort        int
	randomContainerName string
	retStore            ObjectStorage
	ShutdownFunc        func()
}

func NewS3LocalStack(data map[string]string) (*S3LocalStack, error) {
	endPointPort := 4566
	localstack := &S3LocalStack{
		endPointPort:        endPointPort,
		randomContainerName: fmt.Sprintf("s3-test-%d-%d", endPointPort, time.Now().UnixNano()),
	}

	retStore, err := localstack.createS3LocalStack(data)
	if err != nil {
		return nil, err
	}
	localstack.retStore = *retStore

	localstack.ShutdownFunc = func() {
		defer func() {
			// print logs
			formmatedLogsScript := fmt.Sprintf(printLocalStackLogsCommand, localstack.randomContainerName)
			logsOutbytes, err := exec.Command("/bin/sh", "-c", formmatedLogsScript).CombinedOutput()
			if err != nil {
				panic("failed to print localStack logs " + err.Error() + string(logsOutbytes))
			}

			fmt.Printf("localstacklogs %s\n", string(logsOutbytes))

			formmatedScript := fmt.Sprintf(localStackStopCommand, localstack.randomContainerName)
			outbytes, err := exec.Command("/bin/sh", "-c", formmatedScript).CombinedOutput()
			if err != nil {
				panic("failed to stop localStack " + err.Error() + string(outbytes))
			}

			err = killPortProcess(localstack.endPointPort)
			if err != nil {
				panic("failed to kill localStack " + err.Error())
			}
		}()
	}

	return localstack, nil

}

func (s3local *S3LocalStack) GetLocalStack() ObjectStorage {
	return s3local.retStore
}

func (s3local *S3LocalStack) startLocalStack() error {
	fmt.Printf("Starting localstack on port %d\n", s3local.endPointPort)

	newPort, err := findFreePort(s3local.endPointPort, s3local.endPointPort+100)
	if err != nil {
		return err
	}
	s3local.endPointPort = newPort
	formattedScript := fmt.Sprintf(startLocalStackScript, newPort, s3local.randomContainerName)
	out, err := exec.Command("/bin/sh", "-c", formattedScript).CombinedOutput()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return errors.New("failed to start localStack " + err.Error() + string(exitErr.Stderr) + string(out))
		}
		return errors.New("failed to start localStack " + err.Error() + string(out))
	}

	fmt.Printf("Started localstack on port %d\n", s3local.endPointPort)
	for i := 0; i < 30; i++ {
		err := s3local.checklocalStackIsAlive()
		if err == nil {
			return nil
		}
		time.Sleep(2 * time.Second)
	}
	// print logs
	formmatedLogsScript := fmt.Sprintf(printLocalStackLogsCommand, s3local.randomContainerName)
	logsOutbytes, err := exec.Command("/bin/sh", "-c", formmatedLogsScript).CombinedOutput()
	if err != nil {
		return errors.New("failed to print localStack logs " + err.Error() + string(logsOutbytes))
	}
	fmt.Printf("localstacklogs %s\n", string(logsOutbytes))
	formmatedScript := fmt.Sprintf(localStackStopCommand, s3local.randomContainerName)
	outbytes, err := exec.Command("/bin/sh", "-c", formmatedScript).CombinedOutput()
	if err != nil {
		fmt.Println(string(outbytes), err.Error())
	}
	_ = killPortProcess(s3local.endPointPort)
	return errors.New("failed to start localStack")
}

func (s3local *S3LocalStack) checklocalStackIsAlive() error {
	// send HTTP request to localStack
	resp, err := http.DefaultClient.Get(fmt.Sprintf("http://localhost:%d", s3local.endPointPort))
	if err != nil {
		return err

	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		buf := new(bytes.Buffer)
		if _, err := buf.ReadFrom(resp.Body); err != nil {
			return err

		}
		bodyStr := buf.String()
		return errors.New("localStack is not alive " + resp.Status + bodyStr)

	}
	return nil
}

func (s3local *S3LocalStack) createS3LocalStack(data map[string]string) (*ObjectStorage, error) {
	//start container
	s3local.startLocalStack()

	s3local.SeedLocalStack(data)
	var err error
	retStore, err := NewS3ObjectStorage(S3Config{
		Endpoint:    fmt.Sprintf("http://localhost:%d", s3local.endPointPort),
		Region:      "us-east-1",
		AccessKey:   "test",
		SecretKey:   "test",
		Prefix:      "/",
		Bucket:      "test-bucket",
		StorageType: "STANDARD",
	})
	if err != nil {
		return nil, errors.New("failed to create new S3ObjectStore " + err.Error())
	}
	if retStore == nil {
		return nil, errors.New("failed to create new S3ObjectStore retStore is nil")
	}
	// return object storage
	return &retStore, nil
}

func (s3local *S3LocalStack) SeedLocalStack(data map[string]string) error {
	sess, err := session.NewSession(&aws.Config{
		Credentials:      credentials.NewStaticCredentials("test", "test", ""),
		Endpoint:         aws.String(fmt.Sprintf("http://localhost:%d", s3local.endPointPort)),
		Region:           aws.String("us-east-1"),
		S3ForcePathStyle: aws.Bool(true), // Set this to true for localstack
	})
	if err != nil {
		return errors.New("failed to create new AWS session " + err.Error())
	}

	// Create an S3 service client
	svc := s3.New(sess)
	bucketName := "test-bucket"
	// Check if the bucket exists
	_, err = svc.HeadBucket(&s3.HeadBucketInput{
		Bucket: aws.String(bucketName),
	})

	// If the bucket doesn't exist, create it
	if err != nil {
		if !strings.Contains(err.Error(), "status code: 404") {
			return errors.New("failed to check if bucket exists " + err.Error())
		}
		_, err = svc.CreateBucket(&s3.CreateBucketInput{
			Bucket: aws.String(bucketName),
		})
		if err != nil {
			return errors.New("failed to create bucket " + err.Error())
		}

		fmt.Printf("Bucket '%s' created successfully\n", bucketName)
	}

	objectName := "posture/resources/9a24c2bc-5bdb-4152-ae9c-1dcb66dd7c5b/5ca3f7c9-f4cc-4d44-a571-5b4c95985c75/rbac.authorization.k8s.io/v1//ClusterRoleBinding/system:controller:expand-controller"

	content := `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"annotations":{"rbac.authorization.kubernetes.io/autoupdate":"true"},"creationTimestamp":"2023-08-07T11:53:12Z","labels":{"kubernetes.io/bootstrapping":"rbac-defaults"},"name":"system:controller:expand-controller","resourceVersion":"157","uid":"fa23adfc-e8ee-49b7-b956-1df6674c9a1a"},"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"system:controller:expand-controller"},"subjects":[{"kind":"ServiceAccount","name":"expand-controller","namespace":"kube-system"}]}`

	for key, value := range data {
		objectName = key
		content = value

		// Upload the object
		_, err = svc.PutObject(&s3.PutObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(objectName),
			Body:   bytes.NewReader([]byte(content)),
		})
		if err != nil {
			return errors.New("failed to upload object " + err.Error())
		}

	}

	return nil

}

func findFreePort(rangeStart, rangeEnd int) (int, error) {
	for port := rangeStart; port <= rangeEnd; port++ {
		address := fmt.Sprintf("localhost:%d", port)
		conn, err := net.DialTimeout("tcp", address, 1*time.Second)
		if conn != nil {
			conn.Close()
		}
		if err != nil { // port is available since we got no response
			return port, nil
		}
		conn.Close()
	}
	return 0, errors.New("no free port found")
}

func killPortProcess(targetPort int) error {
	socks6, err := netstat.TCP6Socks(netstat.NoopFilter)
	if err != nil {
		return err
	}
	socks, err := netstat.TCPSocks(netstat.NoopFilter)
	if err != nil {
		return err
	}
	for _, sock := range append(socks6, socks...) {
		if sock.LocalAddr.Port == uint16(targetPort) {
			if sock.Process == nil {
				continue
			}
			pid := sock.Process.Pid
			process, err := os.FindProcess(pid)
			if err != nil {
				return err
			}
			fmt.Println("Killing process of port", pid, targetPort)

			// Send a SIGTERM signal to the process
			err = process.Signal(syscall.SIGTERM)
			if err != nil {
				return err
			}
			return nil
		}
	}
	return nil
}
