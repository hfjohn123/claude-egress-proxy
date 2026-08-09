package securefs

type PublishMode uint8

const (
	AbsentTarget PublishMode = iota
	PresentTarget
)

type CommitBoundary struct {
	NamespacePublished bool
	TargetDurable      bool
}
type FaultPoint uint8

const (
	BeforeTempWrite FaultPoint = iota
	AfterTempFlush
	AfterPublication
	AfterTargetDurability
)

type Faults interface{ hit(FaultPoint) error }
type NoFaults struct{}

func (NoFaults) hit(FaultPoint) error { return nil }
