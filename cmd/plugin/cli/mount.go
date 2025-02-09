package cli

import (
	"github.com/fenio/pv-mounter/pkg/plugin"
	"github.com/spf13/cobra"
	"log"
)

func mountCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mount <namespace> <pvc-name> <local-mount-point>",
		Short: "Mount a PVC to a local directory",
		Args:  cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			namespace := args[0]
			pvcName := args[1]
			localMountPoint := args[2]
			if err := plugin.Mount(namespace, pvcName, localMountPoint); err != nil {
				log.Fatalf("Failed to mount PVC: %v", err)
			}
			return nil
		},
	}
	return cmd
}
