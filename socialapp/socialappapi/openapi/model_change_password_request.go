/*
 * Socialapp
 *
 * Socialapp is a generic social network.
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package openapi

type ChangePasswordRequest struct {
	OldPassword string `json:"old_password"`

	NewPassword string `json:"new_password"`
}

// AssertChangePasswordRequestRequired checks if the required fields are not zero-ed
func AssertChangePasswordRequestRequired(obj ChangePasswordRequest) error {
	elements := map[string]interface{}{
		"old_password": obj.OldPassword,
		"new_password": obj.NewPassword,
	}
	for name, el := range elements {
		if isZero := IsZeroValue(el); isZero {
			return &RequiredError{Field: name}
		}
	}

	return nil
}

// AssertRecurseChangePasswordRequestRequired recursively checks if required fields are not zero-ed in a nested slice.
// Accepts only nested slice of ChangePasswordRequest (e.g. [][]ChangePasswordRequest), otherwise ErrTypeAssertionError is thrown.
func AssertRecurseChangePasswordRequestRequired(objSlice interface{}) error {
	return AssertRecurseInterfaceRequired(objSlice, func(obj interface{}) error {
		aChangePasswordRequest, ok := obj.(ChangePasswordRequest)
		if !ok {
			return ErrTypeAssertionError
		}
		return AssertChangePasswordRequestRequired(aChangePasswordRequest)
	})
}
