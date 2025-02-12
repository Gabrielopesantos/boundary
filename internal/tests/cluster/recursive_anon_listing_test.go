package cluster

import (
	"strings"
	"testing"

	amapi "github.com/hashicorp/boundary/api/authmethods"
	rolesapi "github.com/hashicorp/boundary/api/roles"
	"github.com/hashicorp/boundary/internal/daemon/controller"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/stretchr/testify/require"
)

// This test validates the fix for ICU-2301
func TestListAnonymousRecursing(t *testing.T) {
	require := require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	amClient := amapi.NewClient(client)
	rolesClient := rolesapi.NewClient(client)
	orgScopeId := "o_1234567890"

	// Create an auth method in org scope for the test
	am, err := amClient.Create(tc.Context(), "password", orgScopeId)
	require.NoError(err)
	require.NotNil(am)

	// We expect to see all three with the normal token
	l, err := amClient.List(tc.Context(), scope.Global.String(), amapi.WithRecursive(true))
	require.NoError(err)
	require.NotNil(l)
	require.Len(l.GetItems().([]*amapi.AuthMethod), 3)

	// Originally we also expect to see all three as anon user
	amClient.ApiClient().SetToken("")
	l, err = amClient.List(tc.Context(), scope.Global.String(), amapi.WithRecursive(true))
	require.NoError(err)
	require.NotNil(l)
	require.Len(l.GetItems().([]*amapi.AuthMethod), 3)

	// Find the global roles and delete them
	rl, err := rolesClient.List(tc.Context(), scope.Global.String())
	require.NoError(err)
	require.NotNil(rl)
	require.Len(rl.GetItems().([]*rolesapi.Role), 2)

	// Find the non-admin one and delete that first
	adminIdx := 0
	defaultIdx := 1
	roles := rl.GetItems().([]*rolesapi.Role)
	if strings.Contains(roles[0].Name, "Default") {
		adminIdx, defaultIdx = 1, 0
	}
	_, err = rolesClient.Delete(tc.Context(), roles[defaultIdx].Id)
	require.NoError(err)
	_, err = rolesClient.Delete(tc.Context(), roles[adminIdx].Id)
	require.NoError(err)

	// Make sure we can't list in global
	_, err = amClient.List(tc.Context(), scope.Global.String())
	require.Error(err)

	// But we can still see 1 when recursing, from the org scope
	l, err = amClient.List(tc.Context(), scope.Global.String(), amapi.WithRecursive(true))
	require.NoError(err)
	require.NotNil(l)
	ams := l.GetItems().([]*amapi.AuthMethod)
	require.Len(ams, 1)
	require.Equal(orgScopeId, ams[0].ScopeId)
}
