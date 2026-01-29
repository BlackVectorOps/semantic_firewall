// -- internal/sandbox/types.go --
package sandbox

// OCI Specification Structures (Minimal subset required for runsc compliance)
// Defined internally to avoid heavy external dependencies.

type Spec struct {
	Version string   `json:"ociVersion"`
	Process *Process `json:"process"`
	Root    *Root    `json:"root"`
	Mounts  []Mount  `json:"mounts"`
	Linux   *Linux   `json:"linux"`
}

type Process struct {
	User            User          `json:"user"`
	Args            []string      `json:"args"`
	Env             []string      `json:"env"`
	Cwd             string        `json:"cwd"`
	Capabilities    *Capabilities `json:"capabilities"`
	Rlimits         []Rlimit      `json:"rlimits"`
	NoNewPrivileges bool          `json:"noNewPrivileges"`
}

type User struct {
	UID int `json:"uid"`
	GID int `json:"gid"`
}

type Capabilities struct {
	Bounding    []string `json:"bounding"`
	Effective   []string `json:"effective"`
	Inheritable []string `json:"inheritable"`
	Permitted   []string `json:"permitted"`
	Ambient     []string `json:"ambient"`
}

type Rlimit struct {
	Type string `json:"type"`
	Hard uint64 `json:"hard"`
	Soft uint64 `json:"soft"`
}

type Root struct {
	Path     string `json:"path"`
	Readonly bool   `json:"readonly"`
}

type Mount struct {
	Destination string   `json:"destination"`
	Type        string   `json:"type"`
	Source      string   `json:"source"`
	Options     []string `json:"options"`
}

type Linux struct {
	Namespaces  []Namespace `json:"namespaces"`
	UIDMappings []IDMapping `json:"uidMappings"`
	GIDMappings []IDMapping `json:"gidMappings"`
	Resources   *Resources  `json:"resources"`
}

type Namespace struct {
	Type string `json:"type"`
}

type IDMapping struct {
	ContainerID int `json:"containerID"`
	HostID      int `json:"hostID"`
	Size        int `json:"size"`
}

type Resources struct {
	Memory *Memory `json:"memory"`
	CPU    *CPU    `json:"cpu"`
	Pids   *Pids   `json:"pids"`
}

type Memory struct {
	Limit int64 `json:"limit"`
}

type CPU struct {
	Shares uint64 `json:"shares"`
}

type Pids struct {
	Limit int64 `json:"limit"`
}
