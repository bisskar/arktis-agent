//go:build windows

package config

import (
	"os"

	"golang.org/x/sys/windows"
)

func replaceStateFile(oldPath, newPath string) error {
	oldName, err := windows.UTF16PtrFromString(oldPath)
	if err != nil {
		return err
	}
	newName, err := windows.UTF16PtrFromString(newPath)
	if err != nil {
		return err
	}
	// Wait for the replacement to reach disk before permitting a proof echo.
	// https://learn.microsoft.com/windows/win32/api/winbase/nf-winbase-movefileexw
	return windows.MoveFileEx(oldName, newName, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

// protectStateFile replaces inherited permissions before SaveState writes any
// bytes. ProgramData commonly grants read access beyond the service identity;
// a Unix-style 0600 mode does not narrow that ACL on Windows.
func protectStateFile(file *os.File) error {
	acl, err := stateACL(0)
	if err != nil {
		return err
	}
	return setProtectedDACL(file.Name(), acl)
}

// protectStateDir runs before the temporary state file is created. The protected
// DACL ensures a newly-created file is private from its first handle, closing
// the create-then-restrict race that would otherwise expose the proof.
func protectStateDir(dir string) error {
	acl, err := stateACL(windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT)
	if err != nil {
		return err
	}
	return setProtectedDACL(dir, acl)
}

func stateACL(inheritance uint32) (*windows.ACL, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return nil, err
	}
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return nil, err
	}

	fullControl := windows.ACCESS_MASK(windows.GENERIC_ALL)
	entries := []windows.EXPLICIT_ACCESS{
		grantFullControl(user.User.Sid, windows.TRUSTEE_IS_USER, fullControl, inheritance),
		grantFullControl(system, windows.TRUSTEE_IS_USER, fullControl, inheritance),
		grantFullControl(
			administrators,
			windows.TRUSTEE_IS_GROUP,
			fullControl,
			inheritance,
		),
	}
	return windows.ACLFromEntries(entries, nil)
}

func setProtectedDACL(path string, acl *windows.ACL) error {
	return windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		nil,
	)
}

func grantFullControl(
	sid *windows.SID,
	trusteeType windows.TRUSTEE_TYPE,
	permissions windows.ACCESS_MASK,
	inheritance uint32,
) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: permissions,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       inheritance,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  trusteeType,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}
}
