package plugin

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func Clean(namespace, pvcName, localMountPoint string) error {
	var umountCmd *exec.Cmd
	if runtime.GOOS == "darwin" {
		umountCmd = exec.Command("umount", localMountPoint)
	} else {
		umountCmd = exec.Command("fusermount", "-u", localMountPoint)
	}
	umountCmd.Stdout = os.Stdout
	umountCmd.Stderr = os.Stderr
	if err := umountCmd.Run(); err != nil {
		return fmt.Errorf("failed to unmount SSHFS: %v", err)
	}

	clientset, err := BuildKubeClient()
	if err != nil {
		return err
	}

	podClient := clientset.CoreV1().Pods(namespace)
	podList, err := podClient.List(metav1.ListOptions{
		LabelSelector: fmt.Sprintf("pvcName=%s", pvcName),
	})
	if err != nil {
		return fmt.Errorf("failed to list pods: %v", err)
	}

	if len(podList.Items) == 0 {
		return fmt.Errorf("no pod found with PVC name label %s", pvcName)
	}

	podName := podList.Items[0].Name
	port := podList.Items[0].Labels["portNumber"]

	pkillCmd := exec.Command("pkill", "-f", fmt.Sprintf("kubectl port-forward pod/%s %s:22", podName, port))
	pkillCmd.Stdout = os.Stdout
	pkillCmd.Stderr = os.Stderr
	if err := pkillCmd.Run(); err != nil {
		return fmt.Errorf("failed to kill port-forward process: %v", err)
	}

	err = podClient.Delete(podName, &metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("failed to delete pod: %v", err)
	}

	return nil
}