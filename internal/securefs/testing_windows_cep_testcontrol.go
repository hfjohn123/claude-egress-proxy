//go:build windows && cep_testcontrol

package securefs

import "golang.org/x/sys/windows"

// BlockLockedMethodAfterAdmissionForTest is an instance-scoped test hook. It
// attaches only to the supplied root's currently-held lock gate, after the
// public method has been admitted but before it performs its syscall.
func BlockLockedMethodAfterAdmissionForTest(root MutableRoot, file LockedFile, entered chan<- struct{}, release <-chan struct{}) error {
	r, ok := root.(*mutableRoot)
	if !ok {
		return ErrUnsafePath
	}
	w, ok := file.(*windowsLockedFile)
	if !ok {
		return ErrUnsafePath
	}
	op, ok := r.op.(*windowsRoot)
	if !ok || w.root != op {
		return ErrUnsafePath
	}
	w.gate.mu.Lock()
	if w.gate.closing || w.gate.afterGateAdmission != nil {
		w.gate.mu.Unlock()
		return ErrClosed
	}
	w.gate.afterGateAdmission = func() {
		close(entered)
		<-release
	}
	w.gate.mu.Unlock()
	return nil
}

// MarkInspectReparseForTest makes only this mutable root report a reparse tag
// for one named inspection. It exercises CleanupReservedTemp's production
// inspection path on hosts where creating a junction is unavailable.
func MarkInspectReparseForTest(root MutableRoot, name string) error {
	r, ok := root.(*mutableRoot)
	if !ok || !validLeaf(name) {
		return ErrUnsafePath
	}
	op, ok := r.op.(*windowsRoot)
	if !ok {
		return ErrUnsafePath
	}
	op.inspectInfoForTest = func(got string, info windows.ByHandleFileInformation) windows.ByHandleFileInformation {
		if got == name {
			info.FileAttributes |= windows.FILE_ATTRIBUTE_REPARSE_POINT
		}
		return info
	}
	return nil
}

// BlockRetainedRotationCallForTest admits one retained-file operation, blocks
// before its identity syscall, then rechecks the same captured handle.
func BlockRetainedRotationCallForTest(file RetainedFile, entered chan<- struct{}, release <-chan struct{}) error {
	w, ok := file.(*windowsRetainedFile)
	if !ok {
		return ErrUnsafePath
	}
	h, err := w.begin()
	if err != nil {
		return err
	}
	defer w.end()
	close(entered)
	<-release
	return w.usable(h)
}
