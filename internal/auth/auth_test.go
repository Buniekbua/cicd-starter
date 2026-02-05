package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKeyTableDriven(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
		want    string
		wantErr error
	}{
		{
			name: "Success: Correct ApiKey",
			headers: http.Header{
				"Authorization": []string{"ApiKey secret-123"},
			},
			want:    "secret-123",
			wantErr: nil,
		},
		{
			name:    "Error: Missing Header",
			headers: http.Header{},
			want:    "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Error: Wrong Prefix (Bearer)",
			headers: http.Header{
				"Authorization": []string{"Bearer some-token"},
			},
			want:    "",
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name: "Error: Missing Token Part",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			want:    "",
			wantErr: errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetAPIKey(tt.headers)

			if tt.wantErr != nil {
				if err == nil {
					t.Fatalf("Expected error: %v, but got nil", tt.wantErr)
				}
				if err.Error() != tt.wantErr.Error() {
					t.Errorf("Got error: %v, want: %v", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("Got: %s, want: %s", got, tt.want)
			}
		})
	}
}
