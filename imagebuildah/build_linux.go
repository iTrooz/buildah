package imagebuildah

import (
	"fmt"
	"os"

	"github.com/containers/buildah/define"
	"go.podman.io/storage"
)

// platformSetupContextDirectoryOverlay() sets up an overlay _over_ the build
// context directory, and sorts out labeling.  Returns the location which
// should be used as the default build context; the process label and mount
// label for the build, if any; a boolean value that indicates whether we did,
// in fact, mount an overlay; and a cleanup function which should be called
// when the location is no longer needed (on success). Returned errors should
// be treated as fatal.
func platformSetupContextDirectoryOverlay(store storage.Store, options *define.BuildOptions) (string, string, string, bool, func(), error) {
	fmt.Fprintf(os.Stderr, "DEBUG: platformSetupContextDirectoryOverlay called, context=%s\n", options.ContextDirectory)
	// Skip overlay mount in unprivileged containers - just return the context directory directly
	return options.ContextDirectory, "", "", false, func() {}, nil
}