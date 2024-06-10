package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"os/exec"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
)

const (
	VolumeExposerImageVersion       = "v0.0.5"
	DefaultUserGroup          int64 = 2137
	DefaultSSHPort            int   = 2137
	ProxySSHPort              int   = 6666
	secretName                      = "ssh-private-key"
	configMapName                   = "ssh-public-key"
)

func Mount(namespace, pvcName, localMountPoint string) error {
	checkSSHFS()

	if err := validateMountPoint(localMountPoint); err != nil {
		return err
	}

	clientset, err := BuildKubeClient()
	if err != nil {
		return err
	}

	pvc, err := checkPVCUsage(clientset, namespace, pvcName)
	if err != nil {
		return err
	}

	canMount, podUsingPVC, err := checkPVAccessMode(clientset, pvc, namespace)
	if err != nil {
		return err
	}

	// Generate the key pair once and use it for both standalone and proxy scenarios
	privateKey, publicKey, err := GenerateKeyPair(2048)
	if err != nil {
		fmt.Printf("Error generating key pair: %v\n", err)
		return err
	}

	err = createSecret(clientset, namespace, secretName, privateKey)
	if err != nil {
		fmt.Printf("Error creating secret: %v\n", err)
		return err
	}

	err = createConfigMap(clientset, namespace, configMapName, publicKey)
	if err != nil {
		fmt.Printf("Error creating configmap: %v\n", err)
		return err
	}

	fmt.Println("Secret and ConfigMap created successfully.")

	if canMount {
		return handleMount(clientset, namespace, pvcName, localMountPoint, privateKey, publicKey)
	} else {
		return handleRWOConflict(clientset, namespace, pvcName, localMountPoint, podUsingPVC, privateKey, publicKey)
	}
}

func validateMountPoint(localMountPoint string) error {
	if _, err := os.Stat(localMountPoint); os.IsNotExist(err) {
		return fmt.Errorf("local mount point %s does not exist", localMountPoint)
	}
	return nil
}

func handleMount(clientset *kubernetes.Clientset, namespace, pvcName, localMountPoint, privateKey, publicKey string) error {

	podName, port, err := setupPod(clientset, namespace, pvcName, publicKey, "standalone", DefaultSSHPort, "")
	if err != nil {
		return err
	}

	if err := waitForPodReady(clientset, namespace, podName); err != nil {
		return err
	}

	if err := setupPortForwarding(namespace, podName, port); err != nil {
		return err
	}

	return mountPVCOverSSH(namespace, podName, port, localMountPoint, pvcName, privateKey)
}

func handleRWOConflict(clientset *kubernetes.Clientset, namespace, pvcName, localMountPoint, podUsingPVC, privateKey, publicKey string) error {

	podName, port, err := setupPod(clientset, namespace, pvcName, publicKey, "proxy", ProxySSHPort, podUsingPVC)
	if err != nil {
		return err
	}

	if err := waitForPodReady(clientset, namespace, podName); err != nil {
		return err
	}

	proxyPodIP, err := getPodIP(clientset, namespace, podName)
	if err != nil {
		return err
	}

	err = createEphemeralContainer(clientset, namespace, podUsingPVC, privateKey, publicKey, proxyPodIP)
	if err != nil {
		return err
	}

	if err := setupPortForwarding(namespace, podName, port); err != nil {
		return err
	}

	return mountPVCOverSSH(namespace, podName, port, localMountPoint, pvcName, privateKey)
}

func createEphemeralContainer(clientset *kubernetes.Clientset, namespace, podName, privateKey, publicKey, proxyPodIP string) error {
	// Retrieve the existing pod to get the volume name
	existingPod, err := clientset.CoreV1().Pods(namespace).Get(context.TODO(), podName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get existing pod: %v", err)
	}

	var volumeName string
	for _, volume := range existingPod.Spec.Volumes {
		if volume.PersistentVolumeClaim != nil && volume.PersistentVolumeClaim.ClaimName != "" {
			volumeName = volume.Name
			break
		}
	}

	if volumeName == "" {
		return fmt.Errorf("failed to find volume name in the existing pod")
	}

	ephemeralContainerName := fmt.Sprintf("volume-exposer-ephemeral-%s", randSeq(5))
	fmt.Printf("Adding ephemeral container %s to pod %s with volume name %s\n", ephemeralContainerName, podName, volumeName)

	runAsUser := DefaultUserGroup
	runAsGroup := DefaultUserGroup
	allowPrivilegeEscalation := false
	readOnlyRootFilesystem := false
	runAsNonRoot := true

	ephemeralContainer := corev1.EphemeralContainer{
		EphemeralContainerCommon: corev1.EphemeralContainerCommon{
			Name:  ephemeralContainerName,
			Image: fmt.Sprintf("bfenski/volume-exposer:%s", VolumeExposerImageVersion),
			Env: []corev1.EnvVar{
				{
					Name:  "ROLE",
					Value: "ephemeral",
				},
				{
					Name:  "SSH_PRIVATE_KEY",
					Value: privateKey,
				},
				{
					Name:  "PROXY_POD_IP",
					Value: proxyPodIP,
				},
				{
					Name:  "SSH_PUBLIC_KEY",
					Value: publicKey,
				},
			},
			SecurityContext: &corev1.SecurityContext{
				AllowPrivilegeEscalation: &allowPrivilegeEscalation,
				ReadOnlyRootFilesystem:   &readOnlyRootFilesystem,
				RunAsNonRoot:             &runAsNonRoot,
				RunAsUser:                &runAsUser,
				RunAsGroup:               &runAsGroup,
				Capabilities: &corev1.Capabilities{
					Drop: []corev1.Capability{"ALL"},
				},
			},
			VolumeMounts: []corev1.VolumeMount{
				{
					Name:      volumeName,
					MountPath: "/volume",
				},
			},
		},
	}

	patchData, err := json.Marshal(map[string]interface{}{
		"spec": map[string]interface{}{
			"ephemeralContainers": []corev1.EphemeralContainer{ephemeralContainer},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to marshal ephemeral container spec: %v", err)
	}

	_, err = clientset.CoreV1().Pods(namespace).Patch(context.TODO(), podName, types.StrategicMergePatchType, patchData, metav1.PatchOptions{}, "ephemeralcontainers")
	if err != nil {
		return fmt.Errorf("failed to patch pod with ephemeral container: %v", err)
	}

	fmt.Printf("Successfully added ephemeral container %s to pod %s\n", ephemeralContainerName, podName)
	return nil
}

func getPodIP(clientset *kubernetes.Clientset, namespace, podName string) (string, error) {
	pod, err := clientset.CoreV1().Pods(namespace).Get(context.TODO(), podName, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to get pod IP: %v", err)
	}
	return pod.Status.PodIP, nil
}

func checkPVAccessMode(clientset *kubernetes.Clientset, pvc *corev1.PersistentVolumeClaim, namespace string) (bool, string, error) {
	pvName := pvc.Spec.VolumeName
	pv, err := clientset.CoreV1().PersistentVolumes().Get(context.TODO(), pvName, metav1.GetOptions{})
	if err != nil {
		return true, "", fmt.Errorf("failed to get PV: %v", err)
	}

	// Assuming pv is now being checked for its AccessModes.
	if contains(pv.Spec.AccessModes, corev1.ReadWriteOnce) {
		podList, err := clientset.CoreV1().Pods(namespace).List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			return true, "", fmt.Errorf("failed to list pods: %v", err)
		}
		for _, pod := range podList.Items {
			for _, volume := range pod.Spec.Volumes {
				if volume.PersistentVolumeClaim != nil && volume.PersistentVolumeClaim.ClaimName == pvc.Name {
					return false, pod.Name, nil
				}
			}
		}
	}
	return true, "", nil
}

func contains(modes []corev1.PersistentVolumeAccessMode, modeToFind corev1.PersistentVolumeAccessMode) bool {
	for _, mode := range modes {
		if mode == modeToFind {
			return true
		}
	}
	return false
}

func checkPVCUsage(clientset *kubernetes.Clientset, namespace, pvcName string) (*corev1.PersistentVolumeClaim, error) {
	pvc, err := clientset.CoreV1().PersistentVolumeClaims(namespace).Get(context.TODO(), pvcName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get PVC: %v", err)
	}
	if pvc.Status.Phase != corev1.ClaimBound {
		return nil, fmt.Errorf("PVC %s is not bound", pvcName)
	}
	return pvc, nil
}

func setupPod(clientset *kubernetes.Clientset, namespace, pvcName, sshKey, role string, sshPort int, originalPodName string) (string, int, error) {
	podName, port := generatePodNameAndPort(pvcName, role)
	pod := createPodSpec(podName, port, pvcName, sshKey, role, sshPort, originalPodName)
	if _, err := clientset.CoreV1().Pods(namespace).Create(context.TODO(), pod, metav1.CreateOptions{}); err != nil {
		return "", 0, fmt.Errorf("failed to create pod: %v", err)
	}
	fmt.Printf("Pod %s created successfully\n", podName)
	return podName, port, nil
}

func waitForPodReady(clientset *kubernetes.Clientset, namespace, podName string) error {
	return wait.PollImmediate(time.Second, 5*time.Minute, func() (bool, error) {
		pod, err := clientset.CoreV1().Pods(namespace).Get(context.TODO(), podName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		for _, cond := range pod.Status.Conditions {
			if cond.Type == corev1.PodReady && cond.Status == corev1.ConditionTrue {
				return true, nil
			}
		}
		return false, nil
	})
}

func setupPortForwarding(namespace, podName string, port int) error {
	cmd := exec.Command("kubectl", "port-forward", fmt.Sprintf("pod/%s", podName), fmt.Sprintf("%d:%d", port, DefaultSSHPort), "-n", namespace)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start port-forward: %v", err)
	}
	time.Sleep(4 * time.Second) // Wait a bit for the port forwarding to establish
	return nil
}

func mountPVCOverSSH(namespace, podName string, port int, localMountPoint, pvcName, privateKey string) error {

	// Create a temporary file to store the private key
	tmpFile, err := ioutil.TempFile("", "ssh_key_*.pem")
	if err != nil {
		return fmt.Errorf("failed to create temporary file for SSH private key: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write([]byte(privateKey)); err != nil {
		return fmt.Errorf("failed to write SSH private key to temporary file: %v", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close temporary file: %v", err)
	}
	sshfsCmd := exec.Command("sshfs", "-o", fmt.Sprintf("IdentityFile=%s", tmpFile.Name()), "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", fmt.Sprintf("ve@localhost:/volume"), localMountPoint, "-p", fmt.Sprintf("%d", port))
	sshfsCmd.Stdout = os.Stdout
	sshfsCmd.Stderr = os.Stderr
	if err := sshfsCmd.Run(); err != nil {
		return fmt.Errorf("failed to mount PVC using SSHFS: %v", err)
	}
	fmt.Printf("PVC %s mounted successfully to %s\n", pvcName, localMountPoint)
	return nil
}

func generatePodNameAndPort(pvcName, role string) (string, int) {
	rand.Seed(time.Now().UnixNano())
	suffix := randSeq(5)
	baseName := "volume-exposer"
	if role == "proxy" {
		baseName = "volume-exposer-proxy"
	}
	podName := fmt.Sprintf("%s-%s", baseName, suffix)
	port := rand.Intn(64511) + 1024 // Generate a random port between 1024 and 65535
	return podName, port
}

func createPodSpec(podName string, port int, pvcName, sshKey, role string, sshPort int, originalPodName string) *corev1.Pod {
	envVars := []corev1.EnvVar{
		{
			Name:  "SSH_KEY",
			Value: sshKey,
		},
		{
			Name:  "SSH_PORT",
			Value: fmt.Sprintf("%d", sshPort),
		},
	}

	// Add the ROLE environment variable if the role is "standalone" or "proxy"
	if role == "standalone" || role == "proxy" {
		envVars = append(envVars, corev1.EnvVar{
			Name:  "ROLE",
			Value: role,
		})
	}

	runAsNonRoot := true
	runAsUser := DefaultUserGroup
	runAsGroup := DefaultUserGroup
	allowPrivilegeEscalation := false
	readOnlyRootFilesystem := false

	container := corev1.Container{
		Name:  "volume-exposer",
		Image: fmt.Sprintf("bfenski/volume-exposer:%s", VolumeExposerImageVersion),
		Ports: []corev1.ContainerPort{
			{
				ContainerPort: int32(sshPort),
			},
		},
		Env: envVars,
		SecurityContext: &corev1.SecurityContext{
			AllowPrivilegeEscalation: &allowPrivilegeEscalation,
			ReadOnlyRootFilesystem:   &readOnlyRootFilesystem,
			Capabilities: &corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
			},
		},
	}

	labels := map[string]string{
		"app":        "volume-exposer",
		"pvcName":    pvcName,
		"portNumber": fmt.Sprintf("%d", port),
	}

	// Add the original pod name label if provided
	if originalPodName != "" {
		labels["originalPodName"] = originalPodName
	}

	podSpec := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:   podName,
			Labels: labels,
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{container},
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot: &runAsNonRoot,
				RunAsUser:    &runAsUser,
				RunAsGroup:   &runAsGroup,
			},
		},
	}

	// Only mount the volume if the role is not "proxy"
	if role != "proxy" {
		container.VolumeMounts = []corev1.VolumeMount{
			{
				MountPath: "/volume",
				Name:      "my-pvc",
			},
		}
		podSpec.Spec.Volumes = []corev1.Volume{
			{
				Name: "my-pvc",
				VolumeSource: corev1.VolumeSource{
					PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
						ClaimName: pvcName,
					},
				},
			},
		}
		// Update the container in the podSpec with the volume mounts
		podSpec.Spec.Containers[0] = container
	}

	return podSpec
}
